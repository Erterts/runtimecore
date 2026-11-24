#pragma once
#include <array>
#include <vector>
#include <cstdint>
#include <algorithm>
#include "graph_struct.hpp"

/* Константы таймера */
constexpr int     WHEEL_BUCKETS  = 256; // 2^8
constexpr int64_t BUCKET_STEP_MS = 20;  // 256 * 20 = 5120 мс ≈ STUB_LAG_MS(5000)

/* Кольцевой таймер для перевода зависших Stub-узлов (TEMP_LAGGING -> Orphan) */
class StubWheel {
public:
    StubWheel() {
        for (auto& slot : wheel_) {
            slot.reserve(64); // Предвыделяем память на старте (0 реаллокаций в горячем цикле)
        }
    }

    void schedule(Pid pid, int64_t now_ms)
    {
        const int64_t target_tick = (now_ms / BUCKET_STEP_MS) + (WHEEL_BUCKETS - 1);
        const std::size_t slot  = static_cast<std::size_t>(target_tick) & (WHEEL_BUCKETS - 1);
        wheel_[slot].push_back(pid);
    }

    /* Догоняющий тик: очищает все прошедшие слоты, даже если интервал между вызовами > 20 мс */
    void tick(int64_t now_ms, PidMap& map)
    {
        const int64_t current_tick = now_ms / BUCKET_STEP_MS;
        if (last_tick_ == 0) {
            last_tick_ = current_tick;
            return;
        }

        const int64_t steps = std::min<int64_t>(current_tick - last_tick_, WHEEL_BUCKETS);
        for (int64_t s = 1; s <= steps; ++s) {
            const std::size_t slot = static_cast<std::size_t>(last_tick_ + s) & (WHEEL_BUCKETS - 1);
            auto& vec = wheel_[slot];

            for (Pid pid : vec) {
                auto it = map.find(pid);
                if (it != map.end() && it->second.flag.load(std::memory_order_relaxed) == Flag::TEMP_LAGGING) {
                    it->second.flag.store(Flag::Orphan, std::memory_order_relaxed); // LAG -> ORPHAN
                }
            }
            vec.clear();
        }
        last_tick_ = current_tick;
    }

private:
    std::array<std::vector<Pid>, WHEEL_BUCKETS> wheel_;
    int64_t last_tick_ = 0;
};

bool upsert_lite(LiteInfo&, PidMap&);
