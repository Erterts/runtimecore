
#include <thread>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <shared_mutex>
#include <chrono>

#include "crc.hpp"
#include "json_io.h"
#include "graph_struct.h"
#include "detect.h"          // прототипы всех 10 правил
#include "delta_cache.h"
#include "snapshot.h"
#include "ns_shutdown.hpp"

// ---------- заглушки (будут реализованы позже)  ----------------------
std::string read_raw();                                    // tmpfs → std::string
void        upsert_lite(const LitePkt&, PidMap&);          // Stub + insert
void        sweep_buckets(PidMap&, int64_t now_ms);        // LAG→ORPHAN
Event       make_event(const LitePkt&);                    // для DeltaCache
void        write_to_tmpfs(const char* path,
                           const std::string& data);       // атомарная запись

// ---------- глобальные контейнеры ------------------------------------
static PidMap     g_pid_map{/* аллокатор */};
static ExecMap    g_exec_map{/* аллокатор */};
static ExecIndex  g_exec_index;

static DeltaCache     g_delta;
static SnapshotRing<> g_ring;


static std::shared_mutex g_exec_mtx;   // RCU-чтения, exclusive-write


struct FullJob { ExecId exec; std::string raw; };
std::mutex                     q_mtx;
std::condition_variable        q_cv;
std::queue<FullJob>            q_full;

// ---------- разделение детекторов -----------------------------------
/*
    DETECTORS_LITE  (запускаются сразу в main-потоке)
        2  Process Orphan
        5  IP Fan-out spike
        10 Container-Escape   

    DETECTORS_DEEP  (heavy-thread, когда FatInfo уже создан)
        1  Reverse Shell
        3  Download-and-Exec
        4  K8s Token Read
        6  Sys-file Rewrite
        7  Temp-dir Exec
        8  Mass chmod 777
        9  SUID Root escalation
*/
constexpr std::array<DetectFn*,3> DETECTORS_LITE = {
    rule_orphan, rule_ip_fanout, rule_container_escape
};
constexpr std::array<DetectFn*,7> DETECTORS_DEEP = {
    rule_reverse_shell, rule_download_exec, rule_k8s_token,
    rule_sysfile_rewrite, rule_tmpdir_exec,
    rule_mass777,       rule_suid_root
};

// ---------- полный разбор json логов + deep-правила ---------------
void full_parser_worker()
{
    while (shutdown::running.load(std::memory_order_relaxed))
    {
        std::unique_lock ql(q_mtx);
        q_cv.wait(ql, []{
            return !q_full.empty() || !shutdown::running.load();
        });
        if (!shutdown::running && q_full.empty()) break;

        FullJob job = std::move(q_full.front());
        q_full.pop();
        ql.unlock();

        auto [fat_ptr, ok] = jp::parse_full(job.raw, g_exec_index);
        if (!ok) continue;

        {
            std::unique_lock wl(g_exec_mtx);        // write-lock
            g_exec_map.emplace(job.exec, fat_ptr);  // вставка FatInfo
        }

        // глубокий ИБ анализ
        {
            std::shared_lock rl(g_exec_mtx);
            for (auto fn : DETECTORS_DEEP)
                if (fn(job.exec, g_pid_map, g_exec_map))
                    apply_risk_flag(job.exec);
        }
    }
}


int main()
{
    using clock = std::chrono::steady_clock;
    shutdown::install(q_cv);          
    std::thread heavy{full_parser_worker};

    int64_t next_sweep_ts   = 0;
    const   int64_t sweep_period_ms = 1000;
// Основной цикл
    while (shutdown::running.load(std::memory_order_relaxed))
    {
        // ---------- читаем сырой лог ---------------
        std::string raw = read_raw();
        if (!shutdown::running) break;
        if (raw.empty())              continue;
        // ----------проверяем целостность пакетов ---------------
        if (fletcher32({reinterpret_cast<const std::byte*>(raw.data()),
                        raw.size()}) != 0)
            continue;                 

        auto lite = jp::parse_lite(raw);
        upsert_lite(lite, g_pid_map);

        // ---------- Запуск тяжелого детекта по готовности парсера ---------------
        {
            std::lock_guard lg(q_mtx);
            q_full.push({lite.exec_id, std::move(raw)});
        }
        q_cv.notify_one();

        /* ---- ЛЁГКИЕ правила (можно определить только по pid_map) ---------------------- */
        {
            std::shared_lock rl(g_exec_mtx);        // читает exec_map (escape)
            for (auto fn : DETECTORS_LITE)
                if (fn(lite.pid, g_pid_map, g_exec_map))
                    apply_risk_flag(lite.pid);
        }

        // ---------- новое событие в дельту ---------------
        g_delta.register_event(make_event(lite));
        /*  подгружаем родительский процесс, если появился, иначе флаг orphan */
        int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                             clock::now().time_since_epoch()).count();
        if (now_ms >= next_sweep_ts) {
            sweep_buckets(g_pid_map, now_ms);
            next_sweep_ts = now_ms + sweep_period_ms;
        }
        /* кэшируем дельту и слепок графа */
        std::string delta_json;
        if (g_delta.flush_if_needed(now_ms, delta_json))
            write_to_tmpfs("/dev/shm/delta.json", delta_json);

        g_ring.maybe_save(g_pid_map, now_ms);
    }

    /* безопасный выход  */
    q_cv.notify_all();
    heavy.join();
    return 0;
}