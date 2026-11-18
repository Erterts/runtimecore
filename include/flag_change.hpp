
#pragma once
#include <array>
#include <vector>
#include <cstdint>
#include "graph_struct.hpp"

/*  Константы таймера  */
constexpr int   WHEEL_BUCKETS   = 256;   // 2^8 
constexpr int64_t BUCKET_STEP_MS = 20;   // 256*20 = 5120 ≈ STUB_LAG_MS(5000)

/*  Класс-обёртка  */
class StubWheel {
public:
    
    void schedule(Pid pid, int64_t now_ms)
    {
        std::size_t slot = ((now_ms / BUCKET_STEP_MS) +  WHEEL_BUCKETS - 1) & (WHEEL_BUCKETS-1);
        wheel_[slot].push_back(pid);
    }
    /*  tick(now, pid_map) – вызывается каждые 20 мс  */
    void tick(int64_t now_ms, PidMap& map)
    {
        std::size_t slot = (now_ms / BUCKET_STEP_MS) & (WHEEL_BUCKETS-1);
        auto& vec = wheel_[slot];
        for (Pid pid : vec)
        {
            auto it = map.find(pid);
            if (it!=map.end() && it->second.flag.load()==Flag::TEMP_LAGGING)
                it->second.flag.store(Flag::Orphan);        // LAG → ORPHAN
        }
        vec.clear();
    }
private:
    std::array<std::vector<Pid>, WHEEL_BUCKETS> wheel_;
};
bool upsert_lite(const LiteInfo&, PidMap&);