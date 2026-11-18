
#include "detect.hpp"
#include <queue>
#include <shared_mutex>


extern std::shared_mutex g_pid_mtx;

/* -------------------------------------------------------------
   BFS-раскраска «Compromised→InRisk» без длинных блокировок
   Сложность O(|subtree|) и максимум 1 µs hold-time на read-lock.
   -------------------------------------------------------------*/
void bfs_propagate_risk(Pid root, PidMap& lite)
{
    std::queue<Pid> q;
    q.push(root);

    while (!q.empty())
    {
        Pid cur = q.front(); q.pop();


        LiteInfo* info = nullptr;
        {
            std::shared_lock rl(g_pid_mtx);          // ≈ 0.5–1 µs
            auto it = lite.find(cur);
            if (it == lite.end())   continue;

            info = &it->second;

            /* если уже помечен – продолжаем спуск, но не ставим флаг */
            Flag old = info->flag.load(std::memory_order_relaxed);
            if (old < Flag::InRisk)
                info->flag.store(Flag::InRisk, std::memory_order_relaxed);

            
            for (const auto& kv : lite)              
                if (kv.second.ppid == cur)
                    q.push(kv.first);
        }
        /* ---- read-lock отпущен; main-thread может писать pids ----- */
    }
}