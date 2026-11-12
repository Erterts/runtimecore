//==============================================================
//  graph_struct.hpp   (updated)
//==============================================================
#pragma once
/*  PURPOSE
    Хранение графа процессов.

    Теперь LiteInfo содержит:
      • pid            – ключ в pid_map (не хранится, задаётся кол-вне)
      • ppid           – прямой родитель
      • gppid          – «родитель родителя» (ppid отцовского процесса);
                         извлекается из соседнего поля входного JSON.
      • ts             – время создания
      • flag           – статус безопасности
    Это поле gppid нужно, чтобы параллельный
    поток-построитель мог быстрее восстанавливать
    расширенную топологию без дополнительных поисков.
*/

/*  ==== TODO ====
    enum class Flag { Clean, InRisk, Compromised,
                      TEMP_LAGGING, Orphan };

    struct LiteInfo {
        Pid         ppid;      // прямой родитель
        Pid         gppid;     // родитель родителя  ← НОВОЕ ПОЛЕ
        int64_t     ts;
        Flag        flag = Flag::Clean;
    };

    struct FatInfo { … }

    using PidMap  = boost::unordered_node_map<Pid, LiteInfo, …>;
    using ExecMap = boost::unordered_flat_map<ExecId, FatInfo, …>;
*/

