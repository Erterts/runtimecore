
#pragma once
#include <unordered_map>
#include <deque>
#include <string>
#include <cstdint>
#include <array>

/* ========= таймауты sliding-window, мс ===================== */
constexpr int64_t FANOUT_WINDOW_MS   = 5'000;   // правило #5
constexpr int64_t FILE_WINDOW_MS     = 10'000;  // 4,6,8,9

/* ===================== вспомогательные ===================== */
template<std::size_t N>
struct RingSet {
    /*  Хранит не более N уникальных строк (IP или path).       */
    bool insert(std::string_view s) {
        if (set_.count(s)) return false;
        if (set_.size() == N) {          // вытеснение FIFO
            set_.erase(order_.front());
            order_.pop_front();
        }
        order_.push_back(std::string(s));
        set_.insert(order_.back());
        return true;
    }
    std::size_t size() const noexcept { return set_.size(); }
private:
    std::deque<std::string>            order_;
    std::unordered_set<std::string>    set_;
};

/* ===================== AuxState ============================ */
struct AuxState
{
    /* -------- IP fan-out  (dst_ip на PID за окно) ----------- */
    struct IpWin {
        RingSet<64> uniq;                // максимум 64 адреса
        int64_t      last_ts = 0;
        void evict_old(int64_t now) {
            if (now - last_ts > FANOUT_WINDOW_MS) uniq = {};
        }
    };
    std::unordered_map<int32_t, IpWin> ip_map;

    inline std::size_t ip_fanout(int32_t pid) const {
        auto it = ip_map.find(pid);
        return it == ip_map.end() ? 0 : it->second.uniq.size();
    }
    inline void reg_ip(int32_t pid, std::string_view dst, int64_t ts)
    {
        auto &win = ip_map[pid];
        win.evict_old(ts);
        win.uniq.insert(dst);
        win.last_ts = ts;
    }

    /* --------- File-based счётчики -------------------------- */
    struct FileEvt {
        int64_t ts;
        uint16_t mode;       // 0 → не chmod
        bool etc_rewrite;    // /etc/… write-truncate
        bool k8s_token;      // /var/run/secrets/…
    };

    std::unordered_map<int32_t, std::deque<FileEvt>> file_map;

    /*  Кладём событие (open/chmod)  -------------------------- */
    void reg_file_event(int32_t pid, int64_t ts,
                        uint16_t mode, bool etc, bool token)
    {
        auto &dq = file_map[pid];
        dq.push_back({ts, mode, etc, token});
        while (!dq.empty() && ts - dq.front().ts > FILE_WINDOW_MS)
            dq.pop_front();
    }

    /*  Правило 4: K8s token read  */
    bool k8s_token_read(int32_t pid) const {
        auto it=file_map.find(pid);
        if(it==file_map.end()) return false;
        for(auto &e: it->second) if(e.k8s_token) return true;
        return false;
    }
    /*  Правило 6: Sys-file rewrite */
    bool sys_write_to_etc(int32_t pid) const {
        auto it=file_map.find(pid);
        if(it==file_map.end()) return false;
        for(auto &e: it->second) if(e.etc_rewrite) return true;
        return false;
    }
    /*  Правило 8: более 5 chmod 777  */
    int chmod_777_count(int32_t pid) const {
        auto it=file_map.find(pid);
        if(it==file_map.end()) return 0;
        int c=0; for(auto &e:it->second) if(e.mode==0777) ++c;
        return c;
    }
    /*  Правило 9: хоть один 4755/6755  */
    bool chmod_suid(int32_t pid) const {
        auto it=file_map.find(pid);
        if(it==file_map.end()) return false;
        for(auto &e:it->second)
            if(e.mode==04755||e.mode==06755) return true;
        return false;
    }
};