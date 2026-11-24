#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <cstdint>
#include "graph_struct.hpp"

struct NodeAdd { Pid id; Pid ppid; Flag flag; uint16_t rules; };
struct NodeUpd { Pid id;          Flag flag; uint16_t rules; };

struct Event
{
    enum class Kind { Add, Upd } kind;
    Pid      id;
    Pid      ppid{0};
    Flag     flag;
    uint16_t rules;
    int64_t  ts;
};

Event make_event(const LiteInfo&, bool is_new) noexcept;

class DeltaCache
{
public:
    DeltaCache() {
        adds_.reserve(1024);
        upds_.reserve(1024);
    }

    void register_event(const Event& ev);
    bool flush_if_needed(int64_t now_epoch_ms, std::string& json_out);
    void set_period(int ms) noexcept { period_ms_ = ms; }

private:
    std::mutex           mtx_;
    int64_t              last_flush_ms_ = 0;
    int                  period_ms_     = 100;
    std::vector<NodeAdd> adds_;
    std::vector<NodeUpd> upds_;
};

extern DeltaCache g_delta;

struct Delta {
    int64_t                     ts;
    const std::vector<NodeAdd>& adds;
    const std::vector<NodeUpd>& upds;
};
