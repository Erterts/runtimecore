
#include "delta_cache.hpp"
#include "json_io.hpp"
#include "graph_struct.hpp"

Event make_event(const LiteInfo& li, bool is_new) noexcept
{
    Event ev;
    ev.kind  = is_new ? Event::Kind::Add : Event::Kind::Upd;
    ev.id    = li.pid;
    ev.ppid  = li.ppid;
    ev.flag  = li.flag.load(std::memory_order_relaxed);
    ev.rules = li.rule_bits.load(std::memory_order_relaxed);
    ev.ts    = li.ts;
    return ev;
}

void DeltaCache::register_event(const Event& ev)
{
    std::lock_guard lk(mtx_);
    switch (ev.kind) {
    case Event::Kind::Add:
        adds_.push_back({ev.id, ev.ppid, ev.flag, ev.rules});
        break;
    case Event::Kind::Upd:
        upds_.push_back({ev.id, ev.flag, ev.rules});
        break;
    }
}

bool DeltaCache::flush_if_needed(int64_t now_epoch_ms, std::string& out)
{
    std::lock_guard lk(mtx_);
    if (last_flush_ms_ == 0) {
        last_flush_ms_ = now_epoch_ms;
    }
    if (now_epoch_ms - last_flush_ms_ < period_ms_) return false;
    if (adds_.empty() && upds_.empty()) return false;

    Delta d{now_epoch_ms, adds_, upds_};
    je::to_delta(d, out);

    adds_.clear();
    upds_.clear();
    last_flush_ms_ = now_epoch_ms;
    return true;
}
