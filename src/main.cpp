
#include <thread>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <filesystem>
#include <chrono>

#include "crc.hpp"             // fletcher32(...)
#include "json_io.h"           // jp::parse_lite / parse_full
#include "graph_struct.h"
#include "detect.h"            // DETECTORS, apply_risk_flag
#include "delta_cache.h"
#include "snapshot.h"
#include "ns_shutdown.h"

// ---------- заглушки (реализуются позже) ---------------------
std::string read_raw();                                   // tmpfs reader
void        upsert_lite(const LitePkt&, PidMap&);         // stub+insert
void        sweep_buckets(PidMap&, int64_t now_ms);       // LAG→ORPHAN
Event       make_event(const LitePkt&);                   // build Event
void        write_to_tmpfs(const char* path,              // atomic rename
                           const std::string& data);

// ---------- глобальные структуры -----------------------------
static PidMap     g_pid_map{/*arena*/};
static ExecMap    g_exec_map{/*arena*/};
static ExecIndex  g_exec_index;

static DeltaCache     g_delta;
static SnapshotRing<> g_ring;

// ---------- потокобезопасная очередь -------------------------
struct FullJob { ExecId exec; std::string raw; };

std::mutex                     q_mtx;
std::condition_variable        q_cv;
std::queue<FullJob>            q_full;

// ---------- раскрытие полной структуры json ------------------------
void full_parser_worker()
{
    while (shutdown::running.load(std::memory_order_relaxed))
    {
        std::unique_lock lk(q_mtx);
        q_cv.wait(lk, []{
            return !q_full.empty() || !shutdown::running.load();
        });

        if (!shutdown::running && q_full.empty())
            break;

        FullJob job = std::move(q_full.front());
        q_full.pop();
        lk.unlock();

        auto [fat, ok] = jp::parse_full(job.raw, g_exec_index);
        if (ok) g_exec_map.emplace(job.exec, std::move(fat));
    }
}

// ---------- Основной код--------------------------------------
int main()
{
    using clock = std::chrono::steady_clock;
    shutdown::install(q_cv);

    std::thread heavy{full_parser_worker};

    int64_t next_sweep_ts   = 0;
    const   int64_t sweep_period_ms = 1000;

    // ---------- Главный цикл--------------------------------------
    while (shutdown::running.load(std::memory_order_relaxed))
    {
        /* 1. чтение сырых данных */
        std::string raw = read_raw();           
        if (!shutdown::running) break;
        if (raw.empty())        continue;

        /* 2. CRC */
        if (fletcher32({reinterpret_cast<const std::byte*>(raw.data()),
                        raw.size()}) != 0)
            continue;                           // битый пакет

        /* 3. лёгкий разбор + insert */
        auto lite = jp::parse_lite(raw);
        upsert_lite(lite, g_pid_map);

        /* 4. ставим задачу тяжёлому потоку */
        {
            std::lock_guard lg(q_mtx);
            q_full.push({lite.exec_id, std::move(raw)});
        }
        q_cv.notify_one();

        /* 5. ИБ анализ */
        for (auto fn : DETECTORS)
            if (fn(lite.pid, g_pid_map, g_exec_map))
                apply_risk_flag(lite.pid);

        /* 6. Добавляем новое событие в дельту */
        g_delta.register_event(make_event(lite));

        /* 7. Подгружаем родительский процесс, если появился, иначе флаг orphan */
        int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                             clock::now().time_since_epoch()).count();
        if (now_ms >= next_sweep_ts)
        {
            sweep_buckets(g_pid_map, now_ms);
            next_sweep_ts = now_ms + sweep_period_ms;
        }

        /* 8. дельта и кэш слепка графа */
        std::string delta_json;
        if (g_delta.flush_if_needed(now_ms, delta_json))
            write_to_tmpfs("/dev/shm/delta.json", delta_json);

        g_ring.maybe_save(g_pid_map, now_ms);
    }

    /* корректное завершение */
    q_cv.notify_all();   // разбудить heavy, если он ждёт
    heavy.join();        // дожидаемся выхода потока
    return 0;
}