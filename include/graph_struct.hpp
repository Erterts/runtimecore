//==============================================================
//  graph_struct.hpp  (с учётом только process_exec + event_type)
//==============================================================
#pragma once
#include <array>
#include <string>
#include <optional>
#include <memory>
#include <vector>
#include <atomic>
#include <cstdint>
#include <boost/unordered/unordered_node_map.hpp>
#include <boost/unordered/unordered_flat_map.hpp>
#include <unordered_set>
#include <memory_resource>

using Pid       = int32_t;
using ContainerId = std::string;          // docker id / sha256 prefix
using ExecId    = std::array<char,32>;    // sha256 (binary)
inline std::unordered_set<std::string> containers;

/* ---------- новый признак: из какого лога пришло событие -----------*/
enum class EventKind : uint8_t {
    ProcExec,     // пришёл из process_exec   (сейчас единственный)
    NetEvent,     // будущий сетевой
    FileOpen,
    FileChmod,
    Unknown
};

enum class RuleId : uint8_t {           
    ReverseShell, Orphan, DownloadExec, K8sTokenRead,
    IpFanout, SysFileRewrite, TempDirExec,
    Mass777, SuidRoot, ContainerEscape
};
/* ---------- флаги безопасности ------------------------------------*/
enum class Flag : uint8_t {
    Clean,
    InRisk,
    Compromised,
    TEMP_LAGGING,
    Orphan
};

/* ---------- Super-root контейнера ----------------------------------*/
struct SuperRoot {
    ContainerId cid;
    int64_t     start_ts;
};

/* ---------- LiteInfo  (≈ 40 байт) ----------------------------------*/
struct LiteInfo {
    Pid pid;
    Pid                        ppid{};
    Pid                        gppid{};
    int64_t                    ts{};
    ExecId   exec_id;
    std::atomic<Flag>          flag{Flag::Clean};
    std::atomic<uint16_t> rule_bits {0}; // какие правила сработали
    std::optional<ContainerId> docker_id;   // host == std::nullopt
    std::optional<uint32_t>    uid;         // может отсутствовать у net/file
    EventKind                  kind = EventKind::ProcExec;
};
/* ---------- FatInfo  (метаданные процесса) -------------------------*/
struct ExecMeta {
    std::optional<std::string> binary;
    std::optional<std::string> arguments;
    std::optional<std::string> cwd;
    std::optional<uint32_t>    uid;
    std::optional<uint32_t>    gid;
    std::vector<std::string>   caps;       // empty if field missing
    uint64_t                   ns_pid{};   // всегда есть
};
struct FatInfo {
    ExecMeta meta;
    std::vector<Pid>             child_pids;
    EventKind                    kind = EventKind::ProcExec;
};

/* ---------- кастомный хешер ExecId ---------------------------------*/
struct ExecHash {
    std::size_t operator()(const ExecId& id) const noexcept {
        std::size_t v;
        std::memcpy(&v, id.data(), sizeof(std::size_t));
        return v;
    }
};

/* ---------- контейнеры с PMR-аллокатором ---------------------------*/
template<typename T> using PMR =
        std::pmr::polymorphic_allocator<T>;

using PidMap  = boost::unordered_node_map<
                    Pid, LiteInfo,
                    std::hash<Pid>, std::equal_to<>,
                    PMR<std::pair<const Pid, LiteInfo>>>;

using ExecMap = boost::unordered_flat_map<
                    ExecId, std::shared_ptr<FatInfo>,
                    ExecHash, std::equal_to<>,
                    PMR<std::pair<const ExecId,
                                  std::shared_ptr<FatInfo>>>>;

/* ---------- фабрика ExecId из 64-символьной hex-строки -------------*/
ExecId make_exec_id(std::string_view hex);   
inline Pid make_superroot(const std::string& cid, int64_t ts,PidMap& lite)
{
    /* отрицательный PID на основе хеша CID */
    Pid super_pid = -static_cast<Pid>(std::hash<std::string>{}(cid));

    /* если уже есть — возвращаем прежний */
    if (lite.find(super_pid) != lite.end()) return super_pid;

    LiteInfo root{};
    root.pid        = super_pid;
    root.ppid       = 0;
    root.ts         = ts;
    root.docker_id  = cid;
    root.flag.store(Flag::Clean);
    root.kind       = EventKind::ProcExec;

    lite.emplace(super_pid, std::move(root));
    containers.insert(cid);
    return super_pid;
}