
#include "json_io.hpp"          // LitePkt
#include "graph_struct.hpp"     // PidMap, LiteInfo, Flag
#include "flag_change.hpp"    // StubWheel
#include <shared_mutex>

/*  Эти объекты объявлены в main.cpp  */
extern std::shared_mutex g_pid_mtx;
extern StubWheel         g_wheel;

/* ------------------------------------------------------------------
   upsert_lite()
   • создаёт новую запись процесса (или обновляет Stub),
   • гарантирует, что родитель присутствует (Stub-Node),
   • ставит Stub в тайм-колесо для автоматического LAG→ORPHAN,
   • возвращает true, если pid был вставлен впервые.
   ------------------------------------------------------------------*/
bool upsert_lite(const LiteInfo& pkt, PidMap& map)
{
    /* 1.  Эксклюзивно блокируем g_pid_map,
           потому что возможна структурная модификация
           (insert / rehash).                                      */
    std::unique_lock ul(g_pid_mtx);

    /* 2.  Вставляем (или берём) существующий узел.                */
    auto [it, inserted] =
        map.try_emplace(pkt.pid);      // node-based map: addr стабильный
    LiteInfo& node = it->second;

    /* 3.  Заполняем/обновляем поля.   
    node.pid = pkt.pid;                            */
    node.ppid  = pkt.ppid;
    node.gppid = pkt.gppid;
    node.ts    = pkt.ts;
    node.kind  = pkt.kind;             // в process_exec = ProcExec
    if (pkt.docker_id)    {             // host ⇒ std::nullopt
         Pid super = make_superroot(*pkt.docker_id, pkt.ts, map);
            if (pkt.ppid == 0)  node.ppid = super;           // подвешиваем к суперкорню
    }

    /*    Если мы пришли на место Stub’а → снимаем LAG-флаг.       */
    if (node.flag == Flag::TEMP_LAGGING)
        node.flag.store(Flag::Clean, std::memory_order_relaxed);

    /* 4.  Гарантируем присутствие родителя.                       */
    if (pkt.ppid != 0 && map.find(pkt.ppid) == map.end())
    {
        LiteInfo stub{};
        stub.flag   = Flag::TEMP_LAGGING;
        stub.ts     = pkt.ts;
        stub.kind   = EventKind::ProcExec;    // тип не важен
        map.emplace(pkt.ppid, std::move(stub));

        /* ставим Stub в timing-wheel: через 5.12 с станет Orphan  */
        g_wheel.schedule(pkt.ppid, pkt.ts);
    }

    /* 5.  Если родитель уже Compromised / InRisk → немедленно
           унаследовать флаг, чтобы не ждать следующего BFS.       */
    if (pkt.ppid != 0) {
        auto par = map.find(pkt.ppid);
        if (par != map.end() &&
            par->second.flag.load(std::memory_order_relaxed) >= Flag::InRisk)
        {
            node.flag.store(Flag::InRisk, std::memory_order_relaxed);
        }
    }

    return inserted;
}