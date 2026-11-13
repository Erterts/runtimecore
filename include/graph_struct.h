#pragma once
#include <optional>
#include <vector>
#include <boost/unordered/unordered_node_map.hpp>
#include <boost/unordered/unordered_flat_map.hpp>
#include <memory>

/*  PURPOSE
    Единый заголовок всех структур графа процессов.

    LiteInfo  – минимальная запись: PID-топология и флаги безопасности.  
    FatInfo   – «тяжёлая» запись для exec_id: метаданные + список детей.  
    SuperRoot – описание контейнерного суперкорня (виртуальная вершина).
*/

/*=================== STATUS/FLAGS ===================*/
enum class Flag : uint8_t {
    Clean,
    InRisk,
    Compromised,
    TEMP_LAGGING,
    Orphan
};

/*=================== Super-root =====================*/
using ContainerId = std::string;         // можно заменить хеш-строкой

struct SuperRoot {
    ContainerId cid;     // container_id
    int64_t     start_ts;// момент первого события контейнера
    // при необходимости сюда добавим namespace / pod-name
};

/*=================== LiteInfo =======================*/
/*
 * хранит ТОЛЬКО то, что нужно для:
 *   • быстрого восстановления топологии (верхние связи)
 *   • маркировки безопасностных флагов
 * память критична, поэтому никаких shared_ptr здесь нет.
 */
struct LiteInfo {
    int32_t     ppid   = 0;              // прямой родитель
    int32_t     gppid  = 0;              // родитель родителя
    int64_t     ts     = 0;              // время старта
    Flag        flag   = Flag::Clean;
    std::optional<SuperRoot> super;      // заполняется ТОЛЬКО
                                         // у виртуальной вершины контейнера
};

/*=================== FatInfo ========================*/
/*
 * Полный объект процесса/exec. Здесь память не столь критична,
 * поэтому добавляем список детей для быстрого спуска в поддерево.
 * weak_ptr вверх  + vector<Pid> вниз  → нет циклов и минимальный overhead.
 */
using Pid = int32_t;
using ExecId = std::array<char,32>;      // sha256

struct ExecMeta {
    std::string path;
    std::string user;
    // … другие поля по надобности
};

struct FatInfo {
    ExecMeta meta;

    std::weak_ptr<FatInfo>              parent;     // вверх (не влияет на счётчик)
    std::vector<Pid>                    child_pids; // вниз.   vector<shared_ptr<…>>
                                                    // НЕ нужен: для InRisk обхода
                                                    // хватит pid’ов, экономим память
};

/*=================== Hash-контейнеры ================*/
template<typename T> using PMRAllocator =
        std::pmr::polymorphic_allocator<T>;

using PidMap  = boost::unordered_node_map<
                    Pid, LiteInfo,
                    std::hash<Pid>, std::equal_to<>,
                    PMRAllocator<std::pair<const Pid, LiteInfo>>>;

using ExecMap = boost::unordered_flat_map<
                    ExecId, std::shared_ptr<FatInfo>,
                    std::hash<ExecId>, std::equal_to<>,
                    PMRAllocator<std::pair<const ExecId,
                                           std::shared_ptr<FatInfo>>>>;