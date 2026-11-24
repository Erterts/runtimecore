#include "detect.hpp"
#include <array>
#include <shared_mutex>
#include "delta_cache.hpp"
extern std::shared_mutex g_pid_mtx;

/* -------------------------------------------------------------
   BFS-раскраска «Compromised -> InRisk» без динамических аллокаций
   Сложность O(|subtree|) за счёт интрузивного списка first_child/next_sibling.
   -------------------------------------------------------------*/
void bfs_propagate_risk(Pid root, PidMap& lite)
{
    constexpr std::size_t MAX_BFS_NODES = 1024;
    std::array<Pid, MAX_BFS_NODES> q{};
    std::size_t head = 0;
    std::size_t tail = 0;

    q[tail++] = root;

    while (head != tail)
    {
        const Pid cur = q[head];
        head = (head + 1) & (MAX_BFS_NODES - 1);

        // Lock-per-step: держим read-lock доли микросекунды только на один узел
        std::shared_lock rl(g_pid_mtx);
        auto it = lite.find(cur);
        if (it == lite.end()) continue;

        LiteInfo& info = it->second;

        if (cur != root) {
            const Flag old = info.flag.load(std::memory_order_relaxed);
            // Если узел уже в зоне риска или скомпрометирован — пропускаем повторный спуск (защита от циклов)
            if (old == Flag::InRisk || old == Flag::Compromised) continue;
            if (old == Flag::Clean || old == Flag::Orphan) {
            info.flag.store(Flag::InRisk, std::memory_order_relaxed);
            g_delta.register_event(make_event(info, /*is_new=*/false));
            }
        }

        //  обход детей за O(|children|)
        for (Pid child = info.first_child; child != 0; ) {
            auto cit = lite.find(child);
            if (cit == lite.end()) break;

            const std::size_t next_tail = (tail + 1) & (MAX_BFS_NODES - 1);
            if (next_tail == head) break; // Защита от переполнения кольцевого буфера

            q[tail] = child;
            tail = next_tail;
            child = cit->second.next_sibling;
        }
    }
}
