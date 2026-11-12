//==============================================================
//  snapshot_ring.hpp
//==============================================================
#pragma once
#include "graph_struct.hpp"

/*  PURPOSE
    Кольцевой буфер N снимков лёгкого графа
    (по умолчанию 30 шт. = 5 минут при step 10 c).
*/

/*  ==== TODO ====
    template<size_t N>
    class SnapshotRing {
        public:
          void   maybe_save(const LiteGraph& g, int64_t now);
          bool   load_at(int64_t ts, LiteGraph& out) const;
        private:
          array<LiteGraph,N> ring_;
          array<int64_t,N>   ts_;
    };
*/

/*  ==== UNIT TEST ====
    - save 3 снимка, load_at(now-20) возвращает корректный граф
    - память не превышает N * sizeof(LiteGraph)
*/