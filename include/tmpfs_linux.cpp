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

/* =========================================================================
   [PROJECT CONFIG] — ПОЛЯ ДЛЯ НАСТРОЙКИ ПОД КОНКРЕТНЫЙ ПРОЕКТ
   ========================================================================= */
namespace cfg {
    /
    constexpr size_t MAX_MMAP_SIZE = 512ULL * 1024 * 1024;

    // 2. Таймаут ожидания новых событий в poll() (мс).
    constexpr int POLL_WAIT_MS = 50;

  
    inline const char* DEFAULT_IN_DIR   = "/dev/shm";          // Папка, куда пишет источник 
    inline const char* DEFAULT_OUT_DIR  = "/dev/shm";          // Папка, куда ядро кладёт delta.json
    inline const char* DEFAULT_IN_FILE  = "tetragon.log";      // Имя входного JSONL-файла

    // 4. Имена переменных окружения для переопределения путей в Docker / systemd без пересборки
    inline const char* ENV_IN_DIR       = "RR_IN_DIR";
    inline const char* ENV_OUT_DIR      = "RR_OUT_DIR";
    inline const char* ENV_IN_FILE      = "RR_IN_FILE";
}
/* ========================================================================= */

static fs::path    g_in_dir     = cfg::DEFAULT_IN_DIR;
static fs::path    g_out_dir    = cfg::DEFAULT_OUT_DIR;
static std::string g_in_file    = cfg::DEFAULT_IN_FILE;
static fs::path    g_log_path   = g_in_dir / g_in_file;

static int         g_fd         = -1;
static ino_t       g_last_ino   = 0;
static void*       g_mapped     = MAP_FAILED;
static off_t       g_last_off   = 0;

static int         g_inotify_fd = -1;
static int         g_watch      = -1;
static bool        g_inited     = false;
static std::mutex  g_write_mtx;

static bool reopen_mapped_file()
{
    struct stat st{};
    if (::stat(g_log_path.c_str(), &st) != 0) return false;

    if (g_fd >= 0 && g_mapped != MAP_FAILED && st.st_ino == g_last_ino) {
        return true;
    }

    if (g_mapped != MAP_FAILED) {
        ::munmap(g_mapped, cfg::MAX_MMAP_SIZE);
        g_mapped = MAP_FAILED;
    }
    if (g_fd >= 0) {
        ::close(g_fd);
        g_fd = -1;
    }

    g_fd = ::open(g_log_path.c_str(), O_RDONLY | O_NONBLOCK);
    if (g_fd < 0) return false;

    g_mapped = ::mmap(nullptr, cfg::MAX_MMAP_SIZE, PROT_READ, MAP_SHARED, g_fd, 0);
    if (g_mapped == MAP_FAILED) {
        ::close(g_fd);
        g_fd = -1;
        return false;
    }

    g_last_ino = st.st_ino;
    g_last_off = 0;
    return true;
}

static void drain_inotify()
{
    if (g_inotify_fd < 0) return;
    char ev_buf;
    while (::read(g_inotify_fd, ev_buf, sizeof(ev_buf)) > 0) {}
}

void init_io_paths()
{
    if (g_inited) return;

    if (const char* v = std::getenv(cfg::ENV_IN_DIR))  g_in_dir  = v;
    if (const char* v = std::getenv(cfg::ENV_OUT_DIR)) g_out_dir = v;
    if (const char* v = std::getenv(cfg::ENV_IN_FILE)) g_in_file = v;

    std::error_code ec;
    fs::create_directories(g_in_dir, ec);
    fs::create_directories(g_out_dir, ec);

    g_log_path = g_in_dir / g_in_file;

    int tmp_fd = ::open(g_log_path.c_str(), O_CREAT | O_RDONLY, 0644);
    if (tmp_fd >= 0) ::close(tmp_fd);

    reopen_mapped_file();

    g_inotify_fd = ::inotify_init1(IN_NONBLOCK);
    if (g_inotify_fd >= 0) {
        g_watch = ::inotify_add_watch(g_inotify_fd,
                                      g_in_dir.c_str(),
                                      IN_MODIFY | IN_MOVED_TO | IN_CLOSE_WRITE);
    }

    g_inited = true;
}

static std::string extract_line_zero_copy(off_t file_size)
{
    if (file_size < g_last_off) {
        g_last_off = 0; // Файл был перезаписан/усечён
    }

    if (file_size <= g_last_off || static_cast<size_t>(file_size) > cfg::MAX_MMAP_SIZE) {
        return {};
    }

    const char* base  = static_cast<const char*>(g_mapped);
    const char* start = base + g_last_off;
    size_t      avail = static_cast<size_t>(file_size - g_last_off);

    const void* nl = std::memchr(start, '\n', avail);
    if (!nl) return {}; // Строка ещё не дописана до конца (\n)

    size_t line_len = static_cast<const char*>(nl) - start;
    g_last_off += static_cast<off_t>(line_len + 1);

    if (line_len > 0 && start[line_len - 1] == '\r') {
        --line_len;
    }

    return std::string(start, line_len);
}

std::string read_raw()
{
    if (!g_inited) init_io_paths();
    reopen_mapped_file();
    if (g_fd < 0 || g_mapped == MAP_FAILED) return {};

    struct stat st{};
    if (::fstat(g_fd, &st) == 0) {
        std::string line = extract_line_zero_copy(st.st_size);
        if (!line.empty()) return line;
    }

    if (g_inotify_fd >= 0) {
        pollfd pfd{g_inotify_fd, POLLIN, 0};
        if (::poll(&pfd, 1, cfg::POLL_WAIT_MS) > 0 && (pfd.revents & POLLIN)) {
            drain_inotify();
            reopen_mapped_file();
            if (::fstat(g_fd, &st) == 0) {
                return extract_line_zero_copy(st.st_size);
            }
        }
    }

    return {};
}

void write_to_tmpfs(const char* dst, const std::string& data)
{
    if (!g_inited) init_io_paths();

    fs::path p(dst);
    // Если передан относительный путь ("delta.json") — пишем в g_out_dir; если абсолютный — используем как есть
    fs::path full = p.is_absolute() ? p : (g_out_dir / p);
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
