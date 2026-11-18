
#pragma once
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <string>
#include <cstdint>
#include "graph_struct.hpp"
#include "detect_state.hpp"      
#include "json_io.hpp"


inline constexpr int FANOUT_THR = 8;      // порог IP-fanout (#5)
using DetectFn = bool(Pid, const PidMap&, const ExecMap&, AuxState&);
extern ExecIndex g_exec_index;
/* ================== INLINE-правила ========================= */

inline bool rule_reverse_shell(Pid pid,const PidMap&, const ExecMap& em,AuxState& a)
{
    auto fat = find_fat_by_pid(pid, g_exec_index, em);        // extern из main
    if (!fat || !fat->meta.binary)  return false;
    bool is_shell = fat->meta.binary->ends_with("/sh");
    return is_shell && a.ip_fanout(pid) > 0;
}


inline bool rule_orphan(Pid pid, const PidMap& l, const ExecMap&, AuxState&)
{
    auto it = l.find(pid);
    return it!=l.end() && it->second.ppid==0 &&
           it->second.flag!=Flag::TEMP_LAGGING;
}

inline bool rule_download_exec(Pid pid, const PidMap&, const ExecMap& em,AuxState&)
{
    auto fat = find_fat_by_pid(pid, g_exec_index, em);
    if (!fat || !fat->meta.cwd) return false;
    return fat->meta.cwd->rfind("/tmp", 0) == 0;
}

inline bool rule_k8s_token(Pid pid,const PidMap&,const ExecMap&,AuxState& a)
{ return a.k8s_token_read(pid); }

inline bool rule_ip_fanout(Pid pid,const PidMap&,const ExecMap&,AuxState& a)
{ return a.ip_fanout(pid) > FANOUT_THR; }

inline bool rule_sysfile_rewrite(Pid pid,const PidMap&,const ExecMap&,AuxState& a)
{ return a.sys_write_to_etc(pid); }

inline bool rule_tmpdir_exec(Pid pid,const PidMap&, const ExecMap& em,AuxState&)
{
    auto fat = find_fat_by_pid(pid, g_exec_index, em);
    if (!fat || !fat->meta.binary) return false;
    return fat->meta.binary->rfind("/tmp", 0) == 0;
}

inline bool rule_mass777(Pid pid,const PidMap&,const ExecMap&,AuxState& a)
{ return a.chmod_777_count(pid) > 5; }

inline bool rule_suid_root(Pid pid,const PidMap&,const ExecMap&,AuxState& a)
{ return a.chmod_suid(pid); }

inline bool rule_container_escape(Pid pid,const PidMap& l,const ExecMap&,AuxState&)
{
    auto it=l.find(pid);
    if(it==l.end()) return false;
    Pid ppid=it->second.ppid;
    auto par=l.find(ppid);
    return par!=l.end() &&
           par->second.docker_id.has_value() &&        // parent в контейнере
           !it->second.docker_id.has_value();          // child хостовой
}

/* ---------- массивы правил ---------- */
using DetectPair = std::pair<DetectFn*, RuleId>;

constexpr std::array<DetectPair,3> DETECT_LITE {{
    {rule_orphan,           RuleId::Orphan},
    {rule_ip_fanout,        RuleId::IpFanout},
    {rule_container_escape, RuleId::ContainerEscape}
}};
constexpr std::array<DetectPair,7> DETECT_DEEP {{
    {rule_reverse_shell,    RuleId::ReverseShell},
    {rule_download_exec,    RuleId::DownloadExec},
    {rule_k8s_token,        RuleId::K8sTokenRead},
    {rule_sysfile_rewrite,  RuleId::SysFileRewrite},
    {rule_tmpdir_exec,      RuleId::TempDirExec},
    {rule_mass777,          RuleId::Mass777},
    {rule_suid_root,        RuleId::SuidRoot}
}};


void bfs_propagate_risk(Pid root, PidMap& lite);
/* ---------- расстановка флагов-------------*/
inline void apply_risk_flag(Pid root, RuleId id, PidMap& lite)
{
    auto it = lite.find(root);
    if(it==lite.end()) return;
    it->second.flag.store(Flag::Compromised, std::memory_order_relaxed);
    it->second.rule_bits.fetch_or(1u << uint8_t(id),
                                  std::memory_order_relaxed);
    bfs_propagate_risk(root, lite);
}