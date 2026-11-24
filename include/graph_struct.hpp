#pragma once
#include <array>
#include <string>
#include <string_view>
#include <optional>
#include <memory>
#include <vector>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <boost/unordered/unordered_node_map.hpp>
#include <boost/unordered/unordered_flat_map.hpp>
#include <unordered_set>
#include <memory_resource>

using Pid         = int32_t;
using ContainerId = std::string;       // docker id / sha256 prefix
using ExecId      = std::array<char, 32>; // sha256 (binary)


constexpr uint32_t hash_container_id(std::string_view cid) noexcept {
    if (cid.empty()) return 0; // 0 строго зарезервирован для хоста
    uint32_t h = 2166136261u;
    for (unsigned char c : cid) {
        h ^= c;
        h *= 16777619u;
    }
    return h == 0 ? 1u : h; // Исключаем случайную коллизию с 0 (хостом)
}

enum class EventKind : uint8_t {
    ProcExec,     // пришёл из process_exec
    NetEvent,     // будущий сетевой
    FileOpen,     // файловые взаимодействия
    FileChmod,
    Unknown       // под будущее расширение
};

enum class RuleId : uint8_t {
    ReverseShell, Orphan, DownloadExec, K8sTokenRead,
    IpFanout, SysFileRewrite, TempDirExec,
    Mass777, SuidRoot, ContainerEscape
};

/* ---------- Флаги безопасности ------------------------------------*/
enum class Flag : uint8_t {
    Clean,
    InRisk,
    Compromised,
    TEMP_LAGGING,
    Orphan
};

/* ---------- LiteInfo для лёгкой топологии (ровно 64 байта) --------*/
struct alignas(64) LiteInfo {
    ExecId                exec_id{};
    int64_t               ts{};
    Pid                   pid{0};
    Pid                   ppid{0};
    Pid                   first_child{0};     // Голова списка детей (O(|subtree|) BFS)
    Pid                   next_sibling{0};    // Следующий ребёнок того же родителя
    uint32_t              container_hash{0};  
    std::atomic<uint16_t> rule_bits{0};
    std::atomic<Flag>     flag{Flag::Clean};
    EventKind             kind{EventKind::ProcExec};

    LiteInfo() = default;

    LiteInfo(const LiteInfo& rhs) noexcept
        : exec_id(rhs.exec_id),
          ts(rhs.ts),
          pid(rhs.pid),
          ppid(rhs.ppid),
          first_child(rhs.first_child),
          next_sibling(rhs.next_sibling),
          container_hash(rhs.container_hash),
          rule_bits(rhs.rule_bits.load(std::memory_order_relaxed)),
          flag(rhs.flag.load(std::memory_order_relaxed)),
          kind(rhs.kind)
    {}

    LiteInfo& operator=(const LiteInfo& rhs) noexcept {
        if (this != &rhs) {
            exec_id        = rhs.exec_id;
            ts             = rhs.ts;
            pid            = rhs.pid;
            ppid           = rhs.ppid;
            first_child    = rhs.first_child;
            next_sibling   = rhs.next_sibling;
            container_hash = rhs.container_hash;
            rule_bits.store(rhs.rule_bits.load(std::memory_order_relaxed), std::memory_order_relaxed);
            flag.store(rhs.flag.load(std::memory_order_relaxed), std::memory_order_relaxed);
            kind           = rhs.kind;
        }
        return *this;
    }
    LiteInfo(LiteInfo&& rhs) noexcept : LiteInfo(static_cast<const LiteInfo&>(rhs)) {}
    LiteInfo& operator=(LiteInfo&& rhs) noexcept { return (*this = static_cast<const LiteInfo&>(rhs)); }
};
static_assert(sizeof(LiteInfo) == 64, "LiteInfo must fit in a single 64B cache line!");

/* ---------- FatInfo (метаданные процесса в PMR-арене) -------------*/
struct ExecMeta {
    std::pmr::string                   binary;
    std::pmr::string                   arguments;
    std::pmr::string                   cwd;
    std::pmr::string                   docker_id; 
    std::optional<uint32_t>            uid;
    std::optional<uint32_t>            gid;
    std::pmr::vector<std::pmr::string> caps;
    uint64_t                           ns_pid{};
    Pid                                gppid{0};  

    explicit ExecMeta(std::pmr::memory_resource* r)
        : binary(r), arguments(r), cwd(r), docker_id(r), caps(r) {}
};

struct FatInfo {
    ExecMeta  meta;
    EventKind kind = EventKind::ProcExec;

    explicit FatInfo(std::pmr::memory_resource* r) : meta(r) {}
};

/* ---------- Кастомный хешер ExecId ---------------------------------*/
struct ExecHash {
    std::size_t operator()(const ExecId& id) const noexcept {
        std::size_t v;
        std::memcpy(&v, id.data(), sizeof(std::size_t));
        return v;
    }
};

/* ---------- Контейнеры с PMR-аллокатором ---------------------------*/
template<typename T> using PMR = std::pmr::polymorphic_allocator<T>;

using PidMap = boost::unordered_node_map<
                   Pid, LiteInfo,
                   std::hash<Pid>, std::equal_to<>,
                   PMR<std::pair<const Pid, LiteInfo>>>;

using ExecMap = boost::unordered_flat_map<
                    ExecId, std::shared_ptr<FatInfo>,
                    ExecHash, std::equal_to<>,
                    PMR<std::pair<const ExecId, std::shared_ptr<FatInfo>>>>;

/* ---------- Фабрика ExecId из 64-символьной hex-строки -------------*/
ExecId make_exec_id(std::string_view hex) noexcept;

/* ---------- Привязка к виртуальному суперкорню по хэшу контейнера -*/
inline Pid make_superroot(uint32_t cid_hash, int64_t ts, PidMap& lite)
{
    if (cid_hash == 0) return 0;

    // Строго отрицательный PID (< 0), исключающий коллизии с реальными PID Linux
    const Pid super_pid = -static_cast<Pid>((cid_hash & 0x7FFFFFFEu) + 1u);

    if (lite.find(super_pid) != lite.end()) return super_pid;

    LiteInfo root{};
    root.pid            = super_pid;
    root.ppid           = 0;
    root.ts             = ts;
    root.container_hash = cid_hash;
    root.flag.store(Flag::Clean, std::memory_order_relaxed);
    root.kind           = EventKind::ProcExec;

    lite.emplace(super_pid, std::move(root));
    return super_pid;
}
