#pragma once

#include <array>
#include <cstdint>
#include "graph_struct.hpp" // Здесь определены Pid и LiteInfo

#ifndef RING_SIZE
#define RING_SIZE 150 // 5 минут истории при шаге 2 секунды
#endif

// Используем стандартный аллокатор для слепков в кольце, чтобы при затирании
// устаревших слотов память освобождалась, а не копилась в монотонной PMR-арене.
using SnapshotGraph = boost::unordered_node_map<Pid, LiteInfo>;

template<std::size_t N = RING_SIZE>
class SnapshotRing {
public:
    /* Сохраняет снимок, если с последней записи прошло >= period_ms_ */
    void maybe_save(const PidMap& current_graph, int64_t now_epoch_ms) {
        std::size_t prev = (head_ + N - 1) % N;
        if (stamp_[prev] != 0 && (now_epoch_ms - stamp_[prev]) < period_ms_) {
            return;
        }

        ring_[head_].clear();
        ring_[head_].reserve(current_graph.size());
        for (const auto& [pid, info] : current_graph) {
            ring_[head_].emplace(pid, info);
        }

        stamp_[head_] = now_epoch_ms;
        head_ = (head_ + 1) % N;
    }

    /* Ищет ближайший снимок не позже ts_epoch_ms в пределах одного шага period_ms_ */
    [[nodiscard]] bool load_at(int64_t ts_epoch_ms, SnapshotGraph& out) const {
        for (std::size_t i = 0; i < N; ++i) {
            std::size_t idx = (head_ + N - 1 - i) % N;
            int64_t snap_ts = stamp_[idx];

            if (snap_ts == 0)                 continue; // Пустой слот
            if (snap_ts > ts_epoch_ms)        continue; // Снимок из будущего
            if (ts_epoch_ms - snap_ts > period_ms_) continue; // Слишком старый

            out = ring_[idx];
            return true;
        }
        return false;
    }

    /* Возвращает самый свежий снимок (удобно для быстрого возврата в Live-режим) */
    [[nodiscard]] bool load_latest(SnapshotGraph& out) const {
        std::size_t prev = (head_ + N - 1) % N;
        if (stamp_[prev] == 0) return false;
        out = ring_[prev];
        return true;
    }

    void set_period(int64_t ms) noexcept { period_ms_ = ms; }

private:
    std::array<SnapshotGraph, N> ring_{};
    std::array<int64_t, N>       stamp_{};
    std::size_t                  head_      = 0;
    int64_t                      period_ms_ = 2000;
};
