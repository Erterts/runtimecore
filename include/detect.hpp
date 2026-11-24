#pragma once
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <string>
#include <cstdint>
#include <shared_mutex>
#include "graph_struct.hpp"
#include "detect_state.hpp"
#include "json_io.hpp"

inline constexpr int FANOUT_THR = 8; // порог IP-fanout (#5)
using DetectFn = bool(Pid, const PidMap&, const ExecMap&, AuxState&);

extern ExecIndex         g_exec_index;
extern std::shared_mutex g_pid_mtx;

/* ================== INLINE-правила ========================= */

inline bool rule_reverse_shell(Pid pid, const PidMap&, const ExecMap& em, AuxState& a)
{
    auto fat = find_fat_by_pid(pid, g_exec_index, em);
    if (!fat || fat->meta.binary.empty()) return false;
    bool is_shell = fat->meta.binary.ends_with("/sh");
    return is_shell && a.ip_fanout(pid) > 0;
}

inline bool rule_orphan(Pid pid, const PidMap& l, const ExecMap&, AuxState&)
{
    auto it = l.find(pid);
    return it != l.end() && it->second.ppid == 0 &&
           it->second.flag.load(std::memory_order_relaxed) != Flag::TEMP_LAGGING;
}

inline bool rule_download_exec(Pid pid, const PidMap&, const ExecMap& em, AuxState&)
{
    auto fat = find_fat_by_pid(pid, g_exec_index, em);
    if (!fat || fat->meta.cwd.empty()) return false;
    return fat->meta.cwd.rfind("/tmp", 0) == 0;
}

inline bool rule_k8s_token(Pid pid, const PidMap&, const ExecMap&, AuxState& a)
{ return a.k8s_token_read(pid); }

inline bool rule_ip_fanout(Pid pid, const PidMap&, const ExecMap&, AuxState& a)
{ return a.ip_fanout(pid) > FANOUT_THR; }

inline bool rule_sysfile_rewrite(Pid pid, const PidMap&, const ExecMap&, AuxState& a)
{ return a.sys_write_to_etc(pid); }

inline bool rule_tmpdir_exec(Pid pid, const PidMap&, const ExecMap& em, AuxState&)
{
    auto fat = find_fat_by_pid(pid, g_exec_index, em);
    if (!fat || fat->meta.binary.empty()) return false;
    return fat->meta.binary.rfind("/tmp", 0) == 0;
}

inline bool rule_mass777(Pid pid, const PidMap&, const ExecMap&, AuxState& a)
{ return a.chmod_777_count(pid) > 5; }

inline bool rule_suid_root(Pid pid, const PidMap&, const ExecMap&, AuxState& a)
{ return a.chmod_suid(pid); }

inline bool rule_container_escape(Pid pid, const PidMap& l, const ExecMap&, AuxState&)
{
    auto it = l.find(pid);
    if (it == l.end()) return false;
    const Pid ppid = it->second.ppid;
    auto par = l.find(ppid);
    return par != l.end() &&
           par->second.container_hash != 0 && // parent в контейнере
           it->second.container_hash == 0;    // child хостовой
}

/* ---------- массивы правил ---------- */
using DetectPair = std::pair<DetectFn*, RuleId>;

constexpr std::array<DetectPair, 3> DETECT_LITE {{
    {rule_orphan,           RuleId::Orphan},
    {rule_ip_fanout,        RuleId::IpFanout},
    {rule_container_escape, RuleId::ContainerEscape}
}};

constexpr std::array<DetectPair, 7> DETECT_DEEP {{
    {rule_reverse_shell,    RuleId::ReverseShell},
    {rule_download_exec,    RuleId::DownloadExec},
    {rule_k8s_token,        RuleId::K8sTokenRead},
    {rule_sysfile_rewrite,  RuleId::SysFileRewrite},
    {rule_tmpdir_exec,      RuleId::TempDirExec},
    {rule_mass777,          RuleId::Mass777},
    {rule_suid_root,        RuleId::SuidRoot}
}};

void bfs_propagate_risk(Pid root, PidMap& lite);

/* ---------- потокобезопасная расстановка флагов -------------*/
inline void apply_risk_flag(Pid root, RuleId id, PidMap& lite)
{
    {
        // Защищаем поиск в g_pid_map от рехэша при вызове из detect_worker
        std::shared_lock rl(g_pid_mtx);
        auto it = lite.find(root);
        if (it == lite.end()) return;
        it->second.flag.store(Flag::Compromised, std::memory_order_relaxed);
        it->second.flag.store(Flag::Compromised, std::memory_order_relaxed);
        it->second.rule_bits.fetch_or(static_cast<uint16_t>(1u << static_cast<uint8_t>(id)),std::memory_order_relaxed);
        g_delta.register_event(make_event(it->second, /*is_new=*/false));
    }
    // Отпускаем read-lock до входа в BFS, где lock берётся пошагово на каждый узел
    bfs_propagate_risk(root, lite);
}
