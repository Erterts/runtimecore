#pragma once
#include <simdjson.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <exception>
#include "graph_struct.hpp"
#include "delta_cache.hpp"
#include "globals.hpp"

class ExecIndex {
public:
    /* true  – вставлено успешно или уже было то же самое exec_id
       false – обнаружен pid-reuse с другим exec_id                */
    bool insert(Pid pid, const ExecId& ex) noexcept {
        auto [it, ok] = pid2exec_.try_emplace(pid, ex);
        if (!ok) return it->second == ex;           // pid встречался
        return exec2pid_.try_emplace(ex, pid).second;
    }

    const ExecId* find_exec(Pid p) const noexcept {
        auto it = pid2exec_.find(p);
        return it == pid2exec_.end() ? nullptr : &it->second;
    }

    Pid find_pid(const ExecId& ex) const noexcept {
        auto it = exec2pid_.find(ex);
        return it == exec2pid_.end() ? -1 : it->second;
    }

private:
    boost::unordered_node_map<Pid, ExecId,
        std::hash<Pid>, std::equal_to<>,
        PMR<std::pair<const Pid, ExecId>>> pid2exec_;

    boost::unordered_flat_map<ExecId, Pid, ExecHash, std::equal_to<>,
        PMR<std::pair<const ExecId, Pid>>> exec2pid_;
};

extern std::pmr::monotonic_buffer_resource arena_fat;

using FatPtr = std::shared_ptr<FatInfo>;

/* -------------------------------------------------------------
   1. Вспомогательные функции
   -------------------------------------------------------------*/
inline bool fast_json_validate(const char* data, size_t len) noexcept
{
    if (!data || len == 0) return false;
    try {
        thread_local simdjson::dom::parser parser;
        return parser.parse(simdjson::padded_string(data, len)).error() == simdjson::SUCCESS;
    } catch (...) {
        return false;
    }
}

static int64_t parse_iso8601_ns(std::string_view s) noexcept {
    if (s.size() < 19) return 0; // YYYY-MM-DDTHH:MM:SS

    auto dig = [](char c) noexcept -> int {
        return (c >= '0' && c <= '9') ? (c - '0') : -1;
    };
    auto num = [&s, dig](std::size_t pos, std::size_t n) noexcept -> int64_t {
        if (pos + n > s.size()) return -1;
        int64_t v = 0;
        for (std::size_t i = 0; i < n; ++i) {
            const int d = dig(s[pos + i]);
            if (d < 0) return -1;
            v = v * 10 + d;
        }
        return v;
    };

    if (s[4] != '-' || s[7] != '-') return 0;
    if (s[10] != 'T' && s[10] != 't' && s[10] != ' ') return 0;
    if (s[13] != ':' || s[16] != ':') return 0;

    const int64_t Y  = num(0, 4);
    const int64_t M  = num(5, 2);
    const int64_t D  = num(8, 2);
    const int64_t hh = num(11, 2);
    const int64_t mm = num(14, 2);
    const int64_t ss = num(17, 2);
    if (Y < 0 || M < 1 || M > 12 || D < 1 || D > 31 ||
        hh < 0 || hh > 23 || mm < 0 || mm > 59 || ss < 0 || ss > 60)
        return 0;

    std::size_t pos = 19;

    int64_t frac_ns = 0;
    if (pos < s.size() && (s[pos] == '.' || s[pos] == ',')) {
        ++pos;
        int digits = 0;
        for (; pos < s.size() && digits < 9; ++pos, ++digits) {
            const int d = dig(s[pos]);
            if (d < 0) break;
            frac_ns = frac_ns * 10 + d;
        }
        while (pos < s.size() && dig(s[pos]) >= 0) ++pos;
        for (; digits < 9; ++digits) frac_ns *= 10;
    }

    int64_t tz_off = 0;
    if (pos < s.size()) {
        const char c = s[pos];
        if (c == 'Z' || c == 'z') {
            ++pos;
        } else if (c == '+' || c == '-') {
            const int64_t sign = (c == '-') ? -1 : +1;
            ++pos;
            const int64_t oh = num(pos, 2);
            if (oh < 0) return 0;
            pos += 2;
            int64_t om = 0;
            if (pos < s.size() && s[pos] == ':') ++pos;
            if (pos + 2 <= s.size()) {
                om = num(pos, 2);
                if (om < 0) return 0;
                pos += 2;
            }
            tz_off = sign * (oh * 3600 + om * 60);
        }
    }

    const int64_t y    = Y - (M <= 2 ? 1 : 0);
    const int64_t era  = (y >= 0 ? y : y - 399) / 400;
    const int64_t yoe  = y - era * 400;
    const int64_t doy  = (153 * (M > 2 ? M - 3 : M + 9) + 2) / 5 + D - 1;
    const int64_t doe  = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const int64_t days = era * 146097 + doe - 719468;

    const int64_t secs = days * 86400 + hh * 3600 + mm * 60 + ss - tz_off;
    return secs * 1'000'000'000 + frac_ns;
}

/* -------------------------------------------------------------
   2. Пространства имён парсинга и сериализации
   -------------------------------------------------------------*/
namespace jp
{
    /* parse_lite : заполняет 64-байтный LiteInfo без аллокаций в куче */
    inline bool parse_lite(const simdjson::padded_string& raw,
                           LiteInfo& out) noexcept
    {
        try {
            thread_local simdjson::ondemand::parser parser;
            simdjson::ondemand::document doc;

            if (parser.iterate(raw).get(doc)) return false;

            simdjson::ondemand::object pe;
            if (doc["process_exec"].get_object().get(pe)) return false;

            simdjson::ondemand::object proc;
            if (pe["process"].get_object().get(proc)) return false;

            int64_t tmp = 0;
            if (proc["pid"].get_int64().get(tmp)) return false;
            out.pid = static_cast<Pid>(tmp);

            simdjson::ondemand::object parent;
            if (!pe["parent"].get_object().get(parent)) {
                if (!parent["pid"].get_int64().get(tmp)) {
                    out.ppid = static_cast<Pid>(tmp);
                }
            }

            std::string_view sv;
            if (proc["exec_id"].get_string().get(sv)) return false;
            out.exec_id = make_exec_id(sv);

            if (!proc["start_time"].get_string().get(sv)) {
                out.ts = parse_iso8601_ns(sv);
            }

            // 32-битный FNV-1a хэш ID контейнера (0 == хост, без строковых аллокаций)
            if (!proc["docker"].get_string().get(sv)) {
                out.container_hash = hash_container_id(sv);
            }

            out.kind = EventKind::ProcExec;
            return true;
        } catch (...) {
            return false;
        }
    }

    /* parse_full : глубокий разбор в PMR-арену arena_fat (чистая функция без побочных эффектов) */
    inline std::pair<FatPtr, bool> parse_full(const simdjson::padded_string& raw) noexcept
    {
        try {
            using namespace simdjson;
            thread_local ondemand::parser p;
            ondemand::document doc;
            if (p.iterate(raw).get(doc)) return {nullptr, false};

            ondemand::object pe, proc;
            if (doc["process_exec"].get_object().get(pe)) return {nullptr, false};
            if (pe["process"].get_object().get(proc))     return {nullptr, false};

            // Выделяем FatInfo напрямую в монолитной арене arena_fat
            auto fat = std::allocate_shared<FatInfo>(PMR<FatInfo>{&arena_fat}, &arena_fat);
            fat->kind = EventKind::ProcExec;

            ExecMeta& m = fat->meta;
            int64_t tmp = 0;
            std::string_view sv;

            if (!proc["uid"].get_int64().get(tmp))        m.uid       = static_cast<uint32_t>(tmp);
            if (!proc["gid"].get_int64().get(tmp))        m.gid       = static_cast<uint32_t>(tmp);
            if (!proc["binary"].get_string().get(sv))     m.binary    = sv;
            if (!proc["arguments"].get_string().get(sv))  m.arguments = sv;
            if (!proc["cwd"].get_string().get(sv))        m.cwd       = sv;
            if (!proc["docker"].get_string().get(sv))     m.docker_id = sv;

            // Извлекаем gppid (прародителя), если присутствует в структуре parent
            ondemand::object parent;
            if (!pe["parent"].get_object().get(parent)) {
                if (!parent["ppid"].get_int64().get(tmp)) {
                    m.gppid = static_cast<Pid>(tmp);
                }
            }

            ondemand::object ns_obj, pid_ns;
            if (!proc["ns"].get_object().get(ns_obj)) {
                if (!ns_obj["pid"].get_object().get(pid_ns)) {
                    if (!pid_ns["inum"].get_int64().get(tmp)) {
                        m.ns_pid = static_cast<uint64_t>(tmp);
                    }
                }
            }

            ondemand::object cap_obj;
            if (!proc["cap"].get_object().get(cap_obj)) {
                if (ondemand::array eff; !cap_obj["effective"].get_array().get(eff)) {
                    for (auto el : eff) {
                        if (!el.get_string().get(sv)) m.caps.emplace_back(sv);
                    }
                }
            }

            return {fat, true};
        } catch (...) {
            return {nullptr, false};
        }
    }
} // namespace jp

namespace je
{
    inline void to_delta(const Delta& d, std::string& out) noexcept
    {
        rapidjson::StringBuffer sb;
        rapidjson::Writer<rapidjson::StringBuffer> w(sb);

        w.StartObject();
        w.Key("_ts"); w.Int64(d.ts);

        if (!d.adds.empty()) {
            w.Key("add"); w.StartArray();
            for (const auto& n : d.adds) {
                w.StartObject();
                w.Key("id");   w.Int(n.id);
                w.Key("ppid"); w.Int(n.ppid);
                w.Key("flag"); w.Int(int(n.flag));
                w.Key("r");    w.Uint(n.rules);
                w.EndObject();
            }
            w.EndArray();
        }
        if (!d.upds.empty()) {
            w.Key("upd"); w.StartArray();
            for (const auto& n : d.upds) {
                w.StartObject();
                w.Key("id");   w.Int(n.id);
                w.Key("flag"); w.Int(int(n.flag));
                w.Key("r");    w.Uint(n.rules);
                w.EndObject();
            }
            w.EndArray();
        }
        w.EndObject();

        out.assign(sb.GetString(), sb.GetSize());
    }
} // namespace je

/* -------------------------------------------------------------
3. Вспомогательная функция: найти FatInfo по pid
-------------------------------------------------------------*/
inline std::shared_ptr<FatInfo> find_fat_by_pid(Pid pid,const ExecIndex& idx,const ExecMap& emap) noexcept
{
const ExecId* ex = idx.find_exec(pid);
if (!ex) return nullptr;
auto it = emap.find(*ex);
return it == emap.end() ? nullptr : it->second;
}
