//==============================================================
//  snapshot_ring.h   (header-only, template)
//==============================================================
#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include "graph_struct.hpp"      // нужен alias LiteGraph = PidMap

/*  PURPOSE
    Кольцевой буфер из N снимков «лёгкого» графа (LiteGraph).
    Сохранение:   maybe_save(g, now)
    Загрузка:     load_at(ts, out)  -> bool (true, если найден близкий)
*/

#ifndef RING_SIZE
#define RING_SIZE 150          // по умолчанию 5 мин при шаге 2 с
#endif

using LiteGraph = PidMap;      // alias, чтобы не плодить template-параметры

template<std::size_t N = RING_SIZE>
class SnapshotRing
{
public:
    /*  Сохраняет снимок, если прошло snapshot_period секунд
        со времени последней записи. */
    void maybe_save(const LiteGraph& g, int64_t now_epoch_ms);

    /*  Пытается найти снимок, чей timestamp <= ts  и
        (ts - stamp) < snapshot_period.
        Если нашёл — копирует в out и возвращает true.        */
    bool load_at(int64_t ts_epoch_ms, LiteGraph& out) const noexcept;

    /*  Устанавливает период между снимками (мс). По умолчанию — 2000. */
    void set_period(int64_t ms) noexcept { period_ms_ = ms; }

private:
    std::array<LiteGraph, N> ring_{};
    std::array<int64_t,  N>  stamp_{};
    std::size_t              head_      = 0;      // куда будем писать
    int64_t                  period_ms_ = 2000;   // 2 сек по умолчанию
};
