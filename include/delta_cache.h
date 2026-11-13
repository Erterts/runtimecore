
#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "graph_struct.h"

/*  PURPOSE
    Накапливает изменения графа между флашами и формирует
    компактный JSON-объект вида:

    {
      "_ts": 1699550123,
      "add":[ { "id":42,"ppid":1,"flag":0 } ],
      "upd":[ { "id":42,"flag":2 } ],
      "del":[ 99 ]
    }
*/

/* --- вспомогательные структуры ----------------------------------- */
struct NodeAdd   { Pid id; Pid ppid; Flag flag; };
struct NodeUpd   { Pid id; Flag flag;          };
struct NodeDel   { Pid id;                     };

struct Event
{
    enum class Kind { Add, Upd, Del } kind;
    Pid   id;
    Pid   ppid;      // только для Add
    Flag  flag;      // для Add / Upd
    int64_t ts;      // timestamp события
};

/* --- класс кэша ---------------------------------------------------- */
class DeltaCache
{
public:
    /* Регистрирует пришедшее событие (вызывается ядром). */
    void register_event(const Event& ev);

    /* Если с момента last_flush прошло ≥ DELTA_PERIOD_MS,
       формирует JSON в json_out и очищает кэш.
       Возвращает true, если был флаш.                      */
    bool flush_if_needed(int64_t now_epoch_ms,
                         std::string& json_out);

    /* Шаг дельты в мс (по умолчанию 100) */
    void set_period(int ms) noexcept { period_ms_ = ms; }

private:
    int64_t last_flush_ms_ = 0;
    int     period_ms_     = 100;

    std::vector<NodeAdd> adds_;
    std::vector<NodeUpd> upds_;
    std::vector<NodeDel> dels_;
};
