#ifdef _WIN32

#include "tmpfs.hpp"
#include <fstream>
#include <filesystem>
#include <cstdlib>
#include <mutex>
#include <thread>
#include <chrono>
/* ПЕРЕД ЗАПУСКОМ
mkdir C:\dev\radar\shm -Force
$env:RR_SHM = "C:\dev\radar\shm"
New-Item -Path "$env:RR_SHM\tetragon.log" -ItemType File -Force
*/
namespace fs = std::filesystem;

static fs::path       g_shm_root;
static fs::path       g_log_path;
static std::ifstream  g_in;
static std::mutex     g_write_mtx;
static std::streampos g_last_pos{0};

void init_io_paths()
{
    const char* env = std::getenv("RR_SHM");
    g_shm_root = env ? fs::path(env) : fs::temp_directory_path() / "rr_shm";
    fs::create_directories(g_shm_root);

    g_log_path = g_shm_root / "tetragon.log";
    g_last_pos = 0;

    if (fs::exists(g_log_path)) {
        g_in.open(g_log_path, std::ios::in | std::ios::binary);
    }
}

std::string read_raw()
{

    if (!g_in.is_open()) {
        if (!fs::exists(g_log_path)) return {};
        g_in.open(g_log_path, std::ios::in | std::ios::binary);
        if (!g_in.is_open()) return {};
    }

    g_in.clear();
    g_in.seekg(g_last_pos);

    std::string line;
    if (!std::getline(g_in, line)) {
        return {}; // Новых данных нет
    }

    // Если уперлись в EOF без символа '\n', строка еще дописывается (сценарий для тестов на генераторе данных).
    // Откатываем курсор и ждем завершения записи на следующей итерации.
    if (g_in.eof()) {
        g_in.clear();
        g_in.seekg(g_last_pos);
        return {};
    }

    g_last_pos = g_in.tellg();

    // Убираем символ '\r', характерный для переносов строк в Windows (\r\n)
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }

    return line;
}

void write_to_tmpfs(const char* dst, const std::string& data)
{
    fs::path full = g_shm_root / fs::path(dst).filename();
    fs::path tmp  = full;
    tmp += ".tmp";

    std::lock_guard lk(g_write_mtx);

    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return;
        out.write(data.data(), static_cast<std::streamsize>(data.size()));
    } // Файл гарантированно закрывается и сбрасывается на диск перед rename

    // Защита от NTFS Sharing Violation, если читатель открыл full в этот же такт
    for (int attempt = 0; attempt < 5; ++attempt) {
        std::error_code ec;
        fs::rename(tmp, full, ec);
        if (!ec) {
            return; // Успешная атомарная подмена
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

#endif // _WIN32
