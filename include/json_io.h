//==============================================================
//  json_io.hpp
//==============================================================
#pragma once
#include "graph_struct.hpp"

/*  PURPOSE
    Быстрый разбор входного JSON (simdjson)
    и экспорт дельт/снимков (rapidjson).
*/

/*  ==== TODO ====
    namespace jp {
        LitePkt parse_lite(const simdjson::padded_string&) noexcept;
        FullPkt parse_full(const simdjson::padded_string&) noexcept;
    }
    namespace je {
        void to_delta (const Delta&, std::string& out) noexcept;
        void to_snapshot(const LiteGraph&, std::string& out) noexcept;
    }
*/

/*  PURPOSE
    Двусторонний индекс:
      pid   -> exec_id
      exec_id -> pid
    Позволяет быстро проверить «уже виделось ли сочетание».
*/

class ExecIndex {
public:
    // возвращает true, если пара новая и успешно добавлена
    bool insert(Pid pid, const ExecId& ex) noexcept {
        auto [it, ok] = pid2exec_.try_emplace(pid, ex);
        if (!ok) return it->second == ex;   // уже был — сверяем
        return exec2pid_.try_emplace(ex, pid).second;
    }

    ExecId& at_pid(Pid p)  { return pid2exec_.at(p); }
    Pid     at_exec(const ExecId& ex) { return exec2pid_.at(ex); }

private:
    boost::unordered_node_map<Pid, ExecId>          pid2exec_;
    boost::unordered_flat_map<ExecId, Pid, ExecHash> exec2pid_;
};