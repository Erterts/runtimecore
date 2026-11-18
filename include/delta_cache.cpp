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
/* ───────────── register_event ─────────────────────────────── */
void DeltaCache::register_event(const Event& ev)
{
    switch (ev.kind) {
    case Event::Kind::Add:
        adds_.push_back({ev.id, ev.ppid, ev.flag, ev.rules});
        break;
    case Event::Kind::Upd:
        upds_.push_back({ev.id,          ev.flag, ev.rules});
        break;
    }
}

/* ───────────── flush_if_needed ────────────────────────────── */
bool DeltaCache::flush_if_needed(int64_t now_ms, std::string& out)
{
    if (now_ms - last_flush_ms_ < period_ms_) return false;

    /* ── векторы пусты – нечего отдавать ────────────────── */
    if (adds_.empty() && upds_.empty())        return false;

    /* ── собираем лёгкий контейнер и сериализуем ────────── */
    Delta d{now_ms, adds_, upds_};     // Delta = простой struct {ts, adds, upds}
    je::to_delta(d, json_out);         // <<< главный вызов

    /* ── обнуляем буферы ────────────────────────────────── */
    adds_.clear();
    upds_.clear();
    last_flush_ms_ = now_ms;
    return true;
}