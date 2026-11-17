//==============================================================
//  globals.hpp   –  корректная инициализация карт с PMR-ареной
//==============================================================
#pragma once
#include <memory_resource>
#include "graph_struct.hpp"   // PidMap / ExecMap

/* ------------------------------------------------------------------
   1.  Создаём monotonic_buffer_resource
       • 8 МБ достаточно, чтобы держать ~200 k процессов +
         10 k FatInfo без фрагментации.
   ------------------------------------------------------------------*/
inline std::pmr::monotonic_buffer_resource arena{ 8 * 1024 * 1024 };

/* ------------------------------------------------------------------
   2.  Конструкторы boost::unordered_* выглядят так:
       map(bucket_count, hash, equal, allocator)
   ------------------------------------------------------------------*/
inline PidMap g_pid_map{
        1024,                                // начальное число бакетов
        std::hash<Pid>{}, std::equal_to<>,
        PMR<std::pair<const Pid, LiteInfo>>{ &arena }   // allocator
};

inline ExecMap g_exec_map{
        1024,
        ExecHash{}, std::equal_to<>,
        PMR<std::pair<const ExecId, std::shared_ptr<FatInfo>>>{ &arena }
};

/*  Теперь все выделения памяти внутри карт идут через `arena`,
    →  0 malloc/free на горячем пути,
    →  15–20 % экономии RSS и немного быстрее rehash.               */
namespace config{
    /* ----------- тайминги основного конвейера ---------------- */
    inline constexpr int   DELTA_PERIOD_MS      = 100;     // flush Δ каждые 100 мс
    inline constexpr int   SNAPSHOT_PERIOD_S    = 2;       // слепок графа каждые 2 с
    inline constexpr int   SWEEP_MS             = 1000;    // проход timing-wheel

    /* ----------- timing-wheel (Stub->Orphan) ----------------- */
    inline constexpr int   BUCKET_STEP_MS       = 20;      // шаг колеса
    inline constexpr int   WHEEL_BUCKETS        = 256;     // 256·20 мс = 5120 мс
    inline constexpr int   STUB_LAG_MS          = WHEEL_BUCKETS * BUCKET_STEP_MS;

    /* ----------- snapshot-ring ------------------------------- */
    inline constexpr std::size_t RING_SIZE       = 150;    // 5 мин / 2 с

    /* ----------- garbage-collect & лимиты -------------------- */
    inline constexpr int   PID_IDLE_TTL_S       = 60;      // чистим «мертвые» процессы
    inline constexpr int   RISK_PROP_LIMIT      = 50'000;  // макс. вершин BFS

    /* ----------- sliding-windows для deep-правил ------------- */
    inline constexpr int   FANOUT_WINDOW_MS     = 5'000;   // правило #5
    inline constexpr int   FILE_WINDOW_MS       = 10'000;  // 4,6,8,9
    inline constexpr int   FANOUT_THR           = 8;       // порог IP-fanout

    /* ----------- PID⇄exec контроль --------------------------- */
    inline constexpr int   EXEC_PID_MISMATCH_MAX = 3;      // допуски ошибок

    /* ----------- системные лимиты ---------------------------- */
    inline constexpr std::size_t TMPFS_LIMIT_MB  = 2'048;  // /dev/shm size
    inline constexpr std::size_t ARENA_SIZE_MB   = 8;      // PMR monotic arena

    /* ----------- общее --------------------------------------- */
    inline constexpr int   MAX_RULES            = 10;      // число детект-функций
}