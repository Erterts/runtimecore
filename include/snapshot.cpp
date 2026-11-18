
#include "snapshot.hpp"

/*  Алгоритм
    • ring_[head_] всегда указывает, куда будет сделана следующая запись.
    • В массиве stamp_ значение 0 означает «слот пуст».
    • maybe_save() пишет снимок, если с предыдущей записи прошло ≥ period_ms_.
    • load_at() обходит буфер в обратном порядке, чтобы найти
      ближайший по времени снимок, но не позже `ts_epoch_ms`.
*/

template<std::size_t N>
void SnapshotRing<N>::maybe_save(const LiteGraph& g, int64_t now_ms)
{
    if (stamp_[head_] != 0 &&           // кольцо уже заполнено
        now_ms - stamp_[head_] < period_ms_)
        return;                         
    ring_[head_]  = g;                  
    stamp_[head_] = now_ms;             
    head_ = (head_ + 1) % N;            // двигаем указатель на следующее место записи
}

template<std::size_t N>
bool SnapshotRing<N>::load_at(int64_t ts_ms, LiteGraph& out) const noexcept
{
    /* обходим N слотов, начиная с (head_-1) */
    for (std::size_t i = 0; i < N; ++i) {
        std::size_t idx = (head_ + N - 1 - i) % N;
        int64_t    snap_ts = stamp_[idx];

        if (snap_ts == 0)                 continue;          // пустой слот
        if (snap_ts > ts_ms)              continue;          // будущее
        if (ts_ms - snap_ts > period_ms_) continue;          // слишком древний

        out = ring_[idx];   // копируем найденный срез
        return true;
    }
    return false;   // подходящего снимка не нашлось
}

template class SnapshotRing< RING_SIZE >;