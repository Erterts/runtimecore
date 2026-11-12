//==============================================================
//  delta_cache.hpp
//==============================================================
#pragma once
#include "graph_struct.hpp"

/*  PURPOSE
    Хранит изменения за последние DELTA_PERIOD_MS,
    формирует JSON-дельту для фронта.
*/

/*  ==== TODO ====
    class DeltaCache {
        public:
          void   register_new(const Event&);
          bool   flush_if_needed(int64_t now, std::string& json_out);
        private:
          int64_t last_flush_ts_;
          vector<NodeUpd> added, updated, removed;
    };
*/

/*  ==== UNIT TEST ====
    - добавляем узел → flush → JSON содержит "add":[…]
    - без изменений за 100 мс → flush_if_needed==false
*/