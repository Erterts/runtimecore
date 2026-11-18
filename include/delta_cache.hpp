
#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "graph_struct.hpp"

/*  PURPOSE
    Накапливает изменения графа между флашами и формирует
    компактный JSON вида

    {
      "_ts" : 1699550123,
      "add" : [ { "id":42,"ppid":1,"flag":0 } ],
      "upd" : [ { "id":42,"flag":2 } ]
    }
*/

/* ---------------- вспомогательные структуры ---------------- */
struct NodeAdd { Pid id; Pid ppid; Flag flag; uint16_t rules; };
struct NodeUpd { Pid id;          Flag flag; uint16_t rules; };

struct Event
{
    enum class Kind { Add, Upd } kind;  
    Pid      id;
    Pid      ppid{0};   // meaningful only for Add
    Flag     flag;
    uint16_t rules;
    int64_t  ts;
};
Event make_event(const LiteInfo&, bool in_new) noexcept; 

/* ---------------- класс кэша -------------------------------- */
class DeltaCache
{
public:
    /* Регистрирует событие ядра. */
    void register_event(const Event& ev);

    /* Формирует JSON, если прошло ≥ period_ms_.  */
    bool flush_if_needed(int64_t now_epoch_ms,
                         std::string& json_out);

    void set_period(int ms) noexcept { period_ms_ = ms; }

private:
    int64_t last_flush_ms_ = 0;
    int     period_ms_     = 100;
    std::vector<NodeAdd> adds_;
    std::vector<NodeUpd> upds_;
};
struct Delta {
    int64_t                    ts;
    const std::vector<NodeAdd>& adds;
    const std::vector<NodeUpd>& upds;
};