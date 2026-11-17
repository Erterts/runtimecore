
#include <thread>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <shared_mutex>
#include <chrono>
#include "globals.hpp"
#include "cr_check.cpp"
#include "json_io.hpp"
#include "graph_struct.hpp"
#include "detect.hpp"          // все 10 inline-правил
#include "delta_cache.hpp"
#include "snapshot.hpp"
#include "ns_shutdown.hpp"
#include "flag_change.hpp"
#include "upsert_lite.cpp"
#include "detect_state.hpp"
#include "cr_check.hpp"
#include "tmpfs.hpp"
#include "simdjson.h"
// ─── заглушки (реализуем потом) ────────────────────────────────────
std::string read_raw();                        // tmpfs reader
Event       make_event(const LiteInfo&);
void        write_to_tmpfs(const char*, const std::string&);

// ─── глобальные контейнеры ─────────────────────────────────────────

static ExecIndex      g_exec_index;
static AuxState g_aux;
static DeltaCache     g_delta;
static SnapshotRing<> g_ring;
static StubWheel      g_wheel;
// ─── мьютексы для карт (reader/writer) ─────────────────────────────
static std::shared_mutex g_pid_mtx;
static std::shared_mutex g_exec_mtx;

// ───  очереди  ─────────────────────────────────────────────────────
// 1) JSON-строки heavy-парсеру
struct FullJob { Pid pid; Pid ppid; ExecId exec_id; std::string raw; };
std::mutex                     q_json_m;
std::condition_variable        q_json_cv;
std::queue<FullJob>            q_json;

// 2) Готовые Pid deep-детектору
std::mutex                     q_det_m;
std::condition_variable        q_det_cv;
std::queue<Pid>                q_det;

// ─── массивы правил ────────────────────────────────────────────────
using DetectPair = std::pair<DetectFn*, RuleId>;

constexpr std::array<DetectPair,3> DETECT_LITE = {{
    {rule_orphan,        RuleId::Orphan},
    {rule_ip_fanout,     RuleId::IpFanout},
    {rule_container_escape, RuleId::ContainerEscape}
}};

constexpr std::array<DetectPair,7> DETECT_DEEP = {{
    {rule_reverse_shell,   RuleId::ReverseShell},
    {rule_download_exec,   RuleId::DownloadExec},
    {rule_k8s_token,       RuleId::K8sTokenRead},
    {rule_sysfile_rewrite, RuleId::SysFileRewrite},
    {rule_tmpdir_exec,     RuleId::TempDirExec},
    {rule_mass777,         RuleId::Mass777},
    {rule_suid_root,       RuleId::SuidRoot}
}};
// ─── worker 1: Heavy JSON → FatInfo → очередь detect  ──────────────
void heavy_parser_worker()
{
    while (shutdown::running.load())
    {
        std::unique_lock lk(q_json_m);
        q_json_cv.wait(lk, []{
            return !q_json.empty() || !shutdown::running.load();
        });
        if (!shutdown::running && q_json.empty()) break;

        FullJob job = std::move(q_json.front()); q_json.pop();
        lk.unlock();

        auto [fat, ok] = jp::parse_full(job.raw, g_exec_index);
        if (!ok) continue;

        {   std::unique_lock wl(g_exec_mtx);
            g_exec_map.emplace(job.exec_id, fat);
            fill_child_pids(job.pid,job.ppid,g_exec_index,g_exec_map);
        }

        /* Pid ребёнка уже известен в LitePkt => кладём в detect-очередь */
        {
            std::lock_guard lg(q_det_m);
            q_det.push(job.pid);               // exec_id==pid в текущем логе благодаря двусторонней связи
        }
        q_det_cv.notify_one();
    }
}

// ─── worker 2: Deep-detect + BFS  (lock-per-step)  ─────────────────
void detect_worker()
{
    while (shutdown::running.load())
    {
        std::unique_lock lk(q_det_m);
        q_det_cv.wait(lk, []{
            return !q_det.empty() || !shutdown::running.load();
        });
        if (!shutdown::running && q_det.empty()) break;

        Pid pid = q_det.front(); q_det.pop();
        lk.unlock();

        /* deep-rules под read-lock exec_map */
        bool alert = false;
        {
            std::shared_lock rl(g_exec_mtx);
            for (auto [fn,id] : DETECT_DEEP)
                alert |= fn(pid, g_pid_map, g_exec_map,g_aux);
        }
        if (!alert) continue;

        /* ─── короткий BFS с lock-per-step ─── */
        std::queue<Pid> q; q.push(pid);
        while (!q.empty())
        {
            Pid cur = q.front(); q.pop();

            std::shared_lock pl(g_pid_mtx);                 // ≤1 µs
            auto it = g_pid_map.find(cur);
            if (it == g_pid_map.end()) continue;

            auto &info = it->second;
            if (info.flag.load() < Flag::InRisk)
                info.flag.store(Flag::InRisk);

            for (const auto& [pid_child, li_child] : g_pid_map)
    if (li_child.ppid == cur)
        q.push(pid_child);
        }
    }
}

// ───  main-thread : Lite-парсинг, быстрые правила, формирования вывода  ─────────
int main()
{   init_io_paths();
    using clk = std::chrono::steady_clock;
    shutdown::install();          // сигналы

    std::thread heavy {heavy_parser_worker};
    std::thread detect{detect_worker };

    int64_t next_tick = 0;
    const   int64_t SWEEP_MS = 1000;

    while (true)
    {
        if(!shutdown::running.load()) break;
        std::string raw = read_raw();
        if (!shutdown::running) break;
        if (raw.empty()) continue;

        //auto crc = fletcher32(std::as_bytes(std::span{raw.data(), raw.size()})); - не нужно, в логах нет контрольной суммы, целостность даёт сам runtime radar
        if(!fast_json_validate(raw.data(), raw.size())) continue;

        LiteInfo lite;
        if (!jp::parse_lite(raw, lite))   continue;     // ошибка → drop
        upsert_lite(lite, g_pid_map);

        /* быстрая проверка правил */
        for (auto [fn, id] : DETECT_LITE)
        if (fn(lite.pid, g_pid_map, g_exec_map, g_aux)) apply_risk_flag(lite.pid, id, g_pid_map);
        /* кладём JSON тяжёлому парсеру */
        {
            std::lock_guard lg(q_json_m);
            q_json.push({lite.pid,lite.ppid,lite.exec_id, std::move(raw)});
        }
        q_json_cv.notify_one();

        /* регистрируем событие для формирование дельты */
        g_delta.register_event(make_event(lite));
        /* проверяем, дошёл ли лог родительского процесса */
        int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                          clk::now().time_since_epoch()).count();
        if (now >= next_tick) {
        g_wheel.tick(now, g_pid_map);
        next_tick = now + BUCKET_STEP_MS;
        }
        //кэш и дельта
        std::string delta;
        if (g_delta.flush_if_needed(now, delta))
            write_to_tmpfs("/dev/shm/delta.json", delta);

        g_ring.maybe_save(g_pid_map, now);
    }

    /* graceful-exit */
    q_json_cv.notify_all();
    q_det_cv.notify_all();
    heavy.join(); 
    detect.join();
    return 0;
}