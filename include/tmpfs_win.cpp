#ifdef _WIN32

#include "tmpfs.hpp"
#include <fstream>
#include <filesystem>
#include <cstdlib>
#include <mutex>
#include <thread>
#include <chrono>

namespace fs = std::filesystem;

/* =========================================================================
   [PROJECT CONFIG] — ПОЛЯ ДЛЯ НАСТРОЙКИ ПОД КОНКРЕТНЫЙ ПРОЕКТ (WINDOWS)
   ========================================================================= */
namespace cfg {
    // 1. Локальные папки-эмуляторы tmpfs на диске C:
    inline const char* DEFAULT_IN_DIR   = "C:\\dev\\runtimecore\\shm";
    inline const char* DEFAULT_OUT_DIR  = "C:\\dev\\runtimecore\\shm";
    inline const char* DEFAULT_IN_FILE  = "tetragon.log";

    // 2. Переменные окружения (совпадают с Linux-версией)
    inline const char* ENV_IN_DIR       = "RR_IN_DIR";
    inline const char* ENV_OUT_DIR      = "RR_OUT_DIR";
    inline const char* ENV_IN_FILE      = "RR_IN_FILE";
}
/* ========================================================================= */

static fs::path       g_in_dir    = cfg::DEFAULT_IN_DIR;
static fs::path       g_out_dir   = cfg::DEFAULT_OUT_DIR;
static std::string    g_in_file   = cfg::DEFAULT_IN_FILE;
static fs::path       g_log_path;

static std::ifstream  g_in;
static std::mutex     g_write_mtx;
static std::streampos g_last_pos{0};
static bool           g_inited = false;

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
    g_last_pos = 0;

    if (fs::exists(g_log_path)) {
        g_in.open(g_log_path, std::ios::in | std::ios::binary);
    }
    g_inited = true;
}

std::string read_raw()
{
    if (!g_inited) init_io_paths();

    if (!g_in.is_open()) {
        if (!fs::exists(g_log_path)) return {};
        g_in.open(g_log_path, std::ios::in | std::ios::binary);
        if (!g_in.is_open()) return {};
    }

    g_in.clear();
    g_in.seekg(g_last_pos);

    std::string line;
    if (!std::getline(g_in, line)) {
        return {};
    }

    // Если дошли до EOF без символа '\n' — строка ещё дописывается, ждём
    if (g_in.eof()) {
        g_in.clear();
        g_in.seekg(g_last_pos);
        return {};
    }

    g_last_pos = g_in.tellg();

    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }

    return line;
}

void write_to_tmpfs(const char* dst, const std::string& data)
{
    if (!g_inited) init_io_paths();

    fs::path p(dst);
    // Если передан Unix-путь вида "/dev/shm/delta.json" на Windows — берём только имя файла
    fs::path full = (p.is_absolute() && p.has_root_name()) ? p : (g_out_dir / p.filename());
    fs::path tmp  = full;
    tmp += ".tmp";

    std::lock_guard lk(g_write_mtx);

    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return;
        out.write(data.data(), static_cast<std::streamsize>(data.size()));
    }

    for (int attempt = 0; attempt < 5; ++attempt) {
        std::error_code ec;
        fs::rename(tmp, full, ec);
        if (!ec) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

#endif // _WIN32
