#include <thread>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <shared_mutex>
#include <chrono>
#include "globals.hpp"
#include "json_io.hpp"
#include "graph_struct.hpp"
#include "detect.hpp"          // все 10 inline-правил + apply_risk_flag
#include "delta_cache.hpp"
#include "snapshot.hpp"
#include "ns_shutdown.hpp"
#include "flag_change.hpp"
#include "detect_state.hpp"
#include "tmpfs.hpp"
#include "simdjson.h"
#include "history_ctrl.hpp"
// ─── Глобальные контейнеры ─────────────────────────────────────────
ExecIndex             g_exec_index;
static AuxState       g_aux;
DeltaCache     g_delta;
static SnapshotRing<> g_ring;
StubWheel             g_wheel;
HistoryController     g_history;
// ─── Мьютексы для карт (Reader / Writer) ───────────────────────────
std::shared_mutex        g_pid_mtx;
static std::shared_mutex g_exec_mtx;

// ─── Очереди между потоками ────────────────────────────────────────
struct FullJob { Pid pid; Pid ppid; ExecId exec_id; std::string raw; };
std::mutex              q_json_m;
std::condition_variable q_json_cv;
std::queue<FullJob>     q_json;

std::mutex              q_det_m;
std::condition_variable q_det_cv;
std::queue<Pid>         q_det;

// ─── Worker 1: Heavy JSON → FatInfo → очередь detect ───────────────
void heavy_parser_worker()
{
    while (shutdown::running.load(std::memory_order_relaxed))
    {
        FullJob job;
        {
            // [LOCK 1: q_json_m] ~30–50 нс (извлечение задания)
            std::unique_lock lk(q_json_m);
            q_json_cv.wait(lk, []{
                return !q_json.empty() || !shutdown::running.load(std::memory_order_relaxed);
            });
            if (!shutdown::running.load(std::memory_order_relaxed) && q_json.empty()) break;

            job = std::move(q_json.front());
            q_json.pop();
        }

        // Тяжёлый SIMD-парсинг в PMR-арену (allocate_shared) выполняется БЕЗ блокировок.
        auto [fat, ok] = jp::parse_full(job.raw);
        if (!ok) continue;

        {
            // [LOCK 2: g_exec_mtx (exclusive write)] ~80–150 нс
            
            std::unique_lock wl(g_exec_mtx);
            if (!g_exec_index.insert(job.pid, job.exec_id)) continue; // Защита от pid-reuse
            g_exec_map.emplace(job.exec_id, std::move(fat));
            
        }

        {
            // [LOCK 3: q_det_m] ~25–40 нс
            std::lock_guard lg(q_det_m);
            q_det.push(job.pid);
        }
        q_det_cv.notify_one();
    }
}

// ─── Worker 2: Deep-detect + единый итеративный BFS O(|subtree|) ───
void detect_worker()
{
    while (shutdown::running.load(std::memory_order_relaxed))
    {
        Pid pid = 0;
        {
            // [LOCK 4: q_det_m] ~30–50 нс
            std::unique_lock lk(q_det_m);
            q_det_cv.wait(lk, []{
                return !q_det.empty() || !shutdown::running.load(std::memory_order_relaxed);
            });
            if (!shutdown::running.load(std::memory_order_relaxed) && q_det.empty()) break;

            pid = q_det.front();
            q_det.pop();
        }

        // Проверяем 7 глубоких правил под разделяемым читающим замком
        bool alert = false;
        RuleId triggered_id{};
        {
            // [LOCK 5: g_exec_mtx (shared read)] ~150–300 нс
            std::shared_lock rl(g_exec_mtx);
            for (auto [fn, id] : DETECT_DEEP) {
                if (fn(pid, g_pid_map, g_exec_map, g_aux)) {
                    alert = true;
                    triggered_id = id;
                    break;
                }
            }
        }

        if (!alert) continue;

        apply_risk_flag(pid, triggered_id, g_pid_map);
    }
}

// ─── Main-поток: Lite-парсинг, быстрые правила, сброс дельт ────────
#ifndef CATCH_CONFIG_MAIN
int main()
{
    init_io_paths();
    using clk = std::chrono::steady_clock;
    shutdown::install();

    std::thread heavy {heavy_parser_worker};
    std::thread detect{detect_worker};

    int64_t next_tick = 0;

    while (true)
    {
        if (!shutdown::running.load(std::memory_order_relaxed)) break;
        std::string raw = read_raw();
        if (!shutdown::running.load(std::memory_order_relaxed)) break;

        if (!raw.empty()) {
            if (fast_json_validate(raw.data(), raw.size())) {
                LiteInfo lite;
                if (jp::parse_lite(raw, lite)) {
                    const bool inserted = upsert_lite(lite, g_pid_map);

                    {
                        std::shared_lock rl(g_exec_mtx);
                        for (auto [fn, id] : DETECT_LITE) {
                            if (fn(lite.pid, g_pid_map, g_exec_map, g_aux)) {
                                apply_risk_flag(lite.pid, id, g_pid_map);
                            }
                        }
                    }

                    {
                        std::lock_guard lg(q_json_m);
                        q_json.push({lite.pid, lite.ppid, lite.exec_id, std::move(raw)});
                    }
                    q_json_cv.notify_one();

                    g_delta.register_event(make_event(lite, inserted));
                }
            }
        } else {
#ifdef _WIN32
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
#endif
        }

        const int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                                clk::now().time_since_epoch()).count();

        if (now >= next_tick) {
            std::unique_lock wl(g_pid_mtx);
            g_wheel.tick(now, g_pid_map);
            next_tick = now + BUCKET_STEP_MS;
        }

             // 1. Проверяем команды «Машины времени» от фронта (history_mode.json)
     const ControlAction act = g_history.poll();
     if (act == ControlAction::SwitchToHistory) {
         SnapshotGraph snap;
         if (g_ring.load_at(g_history.target_ts(), snap)) {
             std::string snap_json;
             je::to_snapshot(snap, g_history.target_ts(), snap_json);
             write_to_tmpfs("delta.json", snap_json);
         }
     } else if (act == ControlAction::SwitchToLive) {
         SnapshotGraph snap;
         // Берём самый свежий срез из кольца (или актуальный g_pid_map), затираем историю на фронте
         if (!g_ring.load_latest(snap)) {
             std::shared_lock rl(g_pid_mtx);
             for (const auto& [pid, info] : g_pid_map) {
                 snap.emplace(pid, info);
             }
         }
         std::string live_json;
         je::to_snapshot(snap, now, live_json);
         write_to_tmpfs("delta.json", live_json);
         g_delta.clear(); // Очищаем старые дельты, чтобы не было дублей поверх snapshot_restore
     }

     // 2. Обычный сброс инкрементальных дельт (работает ТОЛЬКО в Live-режиме!)
     if (!g_history.is_history_mode()) {
         std::string delta;
         if (g_delta.flush_if_needed(now, delta)) {
             write_to_tmpfs("delta.json", delta);
         }
     }

     // 3. Сохранение слепка в кольцевой буфер (раз в 2000 мс)
     {
         std::shared_lock rl(g_pid_mtx);
         g_ring.maybe_save(g_pid_map, now);
     }

    }

    // Graceful-exit: будим воркеры, чтобы они дочитали остаток очередей до конца
    q_json_cv.notify_all();
    q_det_cv.notify_all();
    heavy.join();
    detect.join();
    return 0;
}
#endif
