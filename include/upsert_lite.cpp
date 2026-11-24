#include "json_io.hpp"          // LiteInfo, make_superroot
#include "graph_struct.hpp"     // PidMap, LiteInfo, Flag
#include "flag_change.hpp"    // StubWheel
#include <shared_mutex>

/* Эти объекты объявлены в main.cpp */
extern std::shared_mutex g_pid_mtx;
extern StubWheel         g_wheel;

/* ------------------------------------------------------------------
   upsert_lite()
   • создаёт новую запись процесса (или обновляет Stub),
   • гарантирует, что родитель присутствует (Stub-Node),
   • сшивает ребёнка в интрузивный список parent.first_child за O(1),
   • ставит Stub в тайм-колесо для автоматического LAG -> ORPHAN,
   • возвращает true, если pid был вставлен впервые (или снят со Stub).
   ------------------------------------------------------------------*/
bool upsert_lite(LiteInfo& pkt, PidMap& map)
{
    /* 1. Эксклюзивно блокируем g_pid_map (в main.cpp перед вызовом лок не ставим!) */
    std::unique_lock ul(g_pid_mtx);

    /* 2. Вставляем новый узел или находим существующую заглушку */
    auto [it, inserted] = map.try_emplace(pkt.pid);
    LiteInfo& node = it->second;

    const Flag prev_flag = node.flag.load(std::memory_order_relaxed);
    const bool was_stub  = (!inserted && prev_flag == Flag::TEMP_LAGGING);

    node.pid            = pkt.pid;
    node.ppid           = pkt.ppid;
    node.ts             = pkt.ts;
    node.exec_id        = pkt.exec_id;
    node.container_hash = pkt.container_hash;
    node.kind           = pkt.kind;

    if (pkt.container_hash != 0) {
        const Pid super = make_superroot(pkt.container_hash, pkt.ts, map);
        if (node.ppid == 0) {
            node.ppid = super; // Подвешиваем корневой процесс контейнера к суперкорню
        }
    }

    /* Если мы пришли на место Stub-заглушки -> снимаем LAG-флаг  */
    if (was_stub) {
        node.flag.store(Flag::Clean, std::memory_order_relaxed);
    }

    /* 4. Гарантируем присутствие родителя и привязываем ребёнка за O(1) */
    const Pid parent_pid = node.ppid;
    if (parent_pid != 0) {
        auto [par_it, par_inserted] = map.try_emplace(parent_pid);
        LiteInfo& parent = par_it->second;

        if (par_inserted) {
            parent.pid  = parent_pid;
            parent.ts   = pkt.ts;
            parent.kind = EventKind::ProcExec;
            parent.flag.store(Flag::TEMP_LAGGING, std::memory_order_relaxed);

            /* Ставим Stub в timing-wheel: через ~5.12 с станет Orphan */
            g_wheel.schedule(parent_pid, pkt.ts);
        }

        /* Добавляем узел в голову списка детей родителя */
        if (inserted || was_stub) {
            node.next_sibling  = parent.first_child;
            parent.first_child = node.pid;
        }

        /* 5. Наследуем риск ТОЛЬКО если родитель реально в зоне риска или скомпрометирован */
        const Flag par_flag = parent.flag.load(std::memory_order_relaxed);
        if (par_flag == Flag::InRisk || par_flag == Flag::Compromised) {
            const Flag cur_flag = node.flag.load(std::memory_order_relaxed);
            if (cur_flag == Flag::Clean) {
                node.flag.store(Flag::InRisk, std::memory_order_relaxed);
            }
        }
    }

    return inserted || was_stub;
}
