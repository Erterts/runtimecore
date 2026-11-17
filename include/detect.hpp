//==============================================================
//  detect.h   (10 inline-правил + контейнеры вызова)
//==============================================================
#pragma once
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <string>
#include <cstdint>
#include "graph_struct.hpp"      // LiteInfo, FatInfo, Pid, Flag
#include "detect_state.hpp"


// ---------- тип сигнатуры любого правила ---------------------
using DetectFn = bool(Pid              pid,
                      const PidMap&    lite,
                      const ExecMap&   exec,
                      AuxState&        aux);   // скользящие окна

// ---------- enum для удобной статистики ----------------------
enum class RuleId : uint8_t {
    ReverseShell = 0,
    Orphan,
    DownloadExec,
    K8sTokenRead,
    IpFanout,
    SysFileRewrite,
    TempDirExec,
    Mass777,
    SuidRoot,
    ContainerEscape
};

/*-------------------------------------------------------------
   10 INLINE-ПРАВИЛ (заглушки-шаблоны; реализация TODO)
  -------------------------------------------------------------*/

inline bool rule_reverse_shell(Pid pid, const PidMap& l, const ExecMap& e, AuxState& a)
{
    // TODO: binary == "/bin/sh" и в AuxState есть внеш. IP
    return false;
}
inline bool rule_orphan(Pid pid, const PidMap& l, const ExecMap&, AuxState&)
{
    auto it = l.find(pid);
    return it!=l.end() && it->second.ppid==0 && it->second.flag!=Flag::TEMP_LAGGING;
}
inline bool rule_download_exec(Pid pid, const PidMap&, const ExecMap& e, AuxState&)
{
    auto it = e.find_by_pid(pid);            // helper: индекс exec_id→ptr
    return it && it->second->meta.cwd          //
                && it->second->meta.cwd->rfind("/tmp",0)==0;
}
inline bool rule_k8s_token(Pid pid,const PidMap&,const ExecMap&,AuxState& a)
{
    return a.k8s_token_read.contains(pid);   // заполнится FileOpen-event
}
inline bool rule_ip_fanout(Pid pid,const PidMap&,const ExecMap&,AuxState& a)
{
    return a.ip_fanout(pid) > FANOUT_THR;    // sliding window
}
inline bool rule_sysfile_rewrite(Pid pid,const PidMap&,const ExecMap&,AuxState& a)
{
    return a.sys_write_to_etc(pid);
}
inline bool rule_tmpdir_exec(Pid pid,const PidMap&,const ExecMap& e,AuxState&)
{
    auto it=e.find_by_pid(pid);
    return it && it->second->meta.binary
           && it->second->meta.binary->rfind("/tmp",0)==0;
}
inline bool rule_mass777(Pid pid,const PidMap&,const ExecMap&,AuxState& a)
{
    return a.chmod_777_count(pid) > 5;
}
inline bool rule_suid_root(Pid pid,const PidMap&,const ExecMap&,AuxState& a)
{
    return a.chmod_suid(pid);
}
inline bool rule_container_escape(Pid pid,const PidMap& l,const ExecMap&,AuxState&)
{
    auto it=l.find(pid);
    if(it==l.end()) return false;
    Pid ppid=it->second.ppid;
    auto par=l.find(ppid);
    return par!=l.end() &&
           par->second.docker_id.has_value() &&
           !it->second.docker_id.has_value();
}

/*-------------------------------------------------------------
  Контейнеры правил для двух потоков
  -------------------------------------------------------------*/
constexpr std::array<DetectFn*,3> DETECT_LITE = {
    rule_orphan,
    rule_ip_fanout,
    rule_container_escape
};
constexpr std::array<DetectFn*,7> DETECT_DEEP = {
    rule_reverse_shell,
    rule_download_exec,
    rule_k8s_token,
    rule_sysfile_rewrite,
    rule_tmpdir_exec,
    rule_mass777,
    rule_suid_root
};

/*-------------------------------------------------------------
  Функция смены флага у заражённого процесса и BFS-раскраска
  -------------------------------------------------------------*/
inline void apply_risk_flag(Pid root, PidMap& lite)
{
    auto it = lite.find(root);
    if(it==lite.end()) return;
    if(it->second.flag.load() < Flag::Compromised)
        it->second.flag.store(Flag::Compromised);
    bfs_propagate_risk(root, lite);      // см. прототип ниже
}

/*  Прототип: lock-per-step BFS, объявлен, но реализуется в .cpp  */
void bfs_propagate_risk(Pid root, PidMap& lite);