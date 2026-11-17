#ifndef _WIN32

#include "tmpfs.hpp"

#include <filesystem>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/inotify.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <mutex>
#include <string>

namespace fs = std::filesystem;

/* ───────────── Константы и глобальные переменные ─────────── */
constexpr size_t MAX_MMAP_SIZE = 2048ULL * 1024 * 1024; // 2 ГБ виртуального окна (соответствует TMPFS_LIMIT_MB)

static fs::path   g_shm_in     = "/dev/shm";
static fs::path   g_shm_out    = "/dev/shm";
static fs::path   g_log_path   = g_shm_in / "tetragon.log";

static int        g_fd         = -1;
static void*      g_mapped     = MAP_FAILED;
static off_t      g_last_off   = 0;

static int        g_inotify_fd = -1;
static int        g_watch      = -1;
static int        N            = 50; //мс ожидания логов
static bool       g_inited     = false;
static std::mutex g_write_mtx;

/* ───────────── Очистка очереди событий inotify ──────────── */
static void drain_inotify()
{
    if (g_inotify_fd < 0) return;
    char ev_buf[256];
    while (::read(g_inotify_fd, ev_buf, sizeof(ev_buf)) > 0) {}
}

/* ───────────── Инициализация путей и mmap ───────────────── */
void init_io_paths()
{
    if (g_inited) return;

    // [DEVOPS SYNC]: согласовать пути файлов в реальной интеграции
    const char* env_base = std::getenv("RR_SHM");
    const char* env_in   = std::getenv("RR_SHM_IN");
    const char* env_out  = std::getenv("RR_SHM_OUT");
    const char* env_file = std::getenv("RR_LOG_FILE");

    if (env_base) {
        g_shm_in  = env_base;
        g_shm_out = env_base;
    }
    if (env_in)  g_shm_in  = env_in;
    if (env_out) g_shm_out = env_out;

    std::error_code ec;
    fs::create_directories(g_shm_in, ec);
    fs::create_directories(g_shm_out, ec);

    std::string filename = env_file ? env_file : "tetragon.log";
    g_log_path = g_shm_in / filename;

    int tmp_fd = ::open(g_log_path.c_str(), O_CREAT | O_RDONLY, 0644);
    if (tmp_fd >= 0) ::close(tmp_fd);

    g_fd = ::open(g_log_path.c_str(), O_RDONLY | O_NONBLOCK);
    if (g_fd < 0) {
        std::perror("open input log");
        return;
    }

    // Проецируем файл напрямую в память без выделения промежуточных буферов
    g_mapped = ::mmap(nullptr, MAX_MMAP_SIZE, PROT_READ, MAP_SHARED, g_fd, 0);
    if (g_mapped == MAP_FAILED) {
        std::perror("mmap input log");
        ::close(g_fd);
        g_fd = -1;
        return;
    }

    g_inotify_fd = ::inotify_init1(IN_NONBLOCK);
    if (g_inotify_fd >= 0) {
        g_watch = ::inotify_add_watch(g_inotify_fd,
                                      g_log_path.c_str(),
                                      IN_MODIFY | IN_ATTRIB);
    }

    g_inited = true;
}

/* ───────────── Поиск строки прямо в памяти mmap ─────────── */
static std::string extract_line_zero_copy(off_t file_size)
{

    if (file_size < g_last_off) {
        g_last_off = 0;
    }

    if (file_size <= g_last_off || static_cast<size_t>(file_size) > MAX_MMAP_SIZE) {
        return {};
    }

    const char* base  = static_cast<const char*>(g_mapped);
    const char* start = base + g_last_off;
    size_t      avail = static_cast<size_t>(file_size - g_last_off);

    // Ищем '\n' прямо в страницах tmpfs без копирования
    const void* nl = std::memchr(start, '\n', avail);
    if (!nl) {
        return {}; // Строка еще дописывается, ждем '\n'
    }

    size_t line_len = static_cast<const char*>(nl) - start;
    g_last_off += static_cast<off_t>(line_len + 1);

    // Убираем '\r', если лог пришел с Windows-переносами
    if (line_len > 0 && start[line_len - 1] == '\r') {
        --line_len;
    }

    // Единственная аллокация: создаем итоговую строку для передачи в очередь
    return std::string(start, line_len);
}

/* ───────────── read_raw() ─────────────────────────────────── */
std::string read_raw()
{
    if (!g_inited) init_io_paths();
    if (g_fd < 0 || g_mapped == MAP_FAILED) return {};

    struct stat st{};
    if (::fstat(g_fd, &st) == 0) {
        std::string line = extract_line_zero_copy(st.st_size);
        if (!line.empty()) return line;
    }

    // Если новых строк нет — ждем события записи через poll до N мс
    if (g_inotify_fd >= 0) {
        pollfd pfd{g_inotify_fd, POLLIN, 0};
        if (::poll(&pfd, 1, N) > 0 && (pfd.revents & POLLIN)) {
            drain_inotify();
            if (::fstat(g_fd, &st) == 0) {
                return extract_line_zero_copy(st.st_size);
            }
        }
    }

    return {};
}

/* ───────────── write_to_tmpfs() ───────────────────────────── */
void write_to_tmpfs(const char* dst, const std::string& data)
{
    if (!g_inited) init_io_paths();

    fs::path full = g_shm_out / fs::path(dst).filename();
    fs::path tmp  = full;
    tmp += ".tmp";

    std::lock_guard lk(g_write_mtx);

    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        std::perror("open tmp");
        return;
    }

    size_t total_written = 0;
    while (total_written < data.size()) {
        ssize_t w = ::write(fd, data.data() + total_written, data.size() - total_written);
        if (w <= 0) {
            if (errno == EINTR) continue;
            break;
        }
        total_written += static_cast<size_t>(w);
    }

    ::close(fd);

    if (total_written == data.size()) {
        ::rename(tmp.c_str(), full.c_str());
    } else {
        ::unlink(tmp.c_str());
    }
}

#endif // !_WIN32
