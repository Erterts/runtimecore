#pragma once
#include <filesystem>
#include <fstream>
#include <string>
#include <cstdint>
#include <cstdlib>
#include <simdjson.h>

enum class ControlAction {
    None,           // Новых команд от фронта нет
    SwitchToHistory,// Запрос исторического среза по target_ts
    SwitchToLive    // Возврат в режим реального времени (очистка истории)
};

class HistoryController {
public:
    HistoryController() {
        const char* env_dir = std::getenv("RR_OUT_DIR");
        if (env_dir && *env_dir) {
            ctrl_path_ = std::filesystem::path(env_dir) / "history_mode.json";
        } else {
#ifdef _WIN32
            ctrl_path_ = std::filesystem::path("C:\\dev\\runtimecore\\shm") / "history_mode.json";
#else
            ctrl_path_ = std::filesystem::path("/dev/shm") / "history_mode.json";
#endif
        }
    }

    // Вызывается в основном цикле main.cpp; проверяет mtime файла за ~1 мкс
    ControlAction poll() noexcept {
        try {
            std::error_code ec;
            if (!std::filesystem::exists(ctrl_path_, ec)) {
                return ControlAction::None;
            }

            const auto mtime = std::filesystem::last_write_time(ctrl_path_, ec);
            if (ec || mtime == last_mtime_) {
                return ControlAction::None;
            }
            last_mtime_ = mtime;

            // Читаем короткий управляющий JSON
            simdjson::padded_string json_buf;
            if (simdjson::padded_string::load(ctrl_path_.string()).get(json_buf)) {
                return ControlAction::None;
            }

            thread_local simdjson::ondemand::parser parser;
            simdjson::ondemand::document doc;
            if (parser.iterate(json_buf).get(doc)) {
                return ControlAction::None;
            }

            std::string_view mode_sv;
            if (doc["mode"].get_string().get(mode_sv)) {
                return ControlAction::None;
            }

            if (mode_sv == "history") {
                int64_t ts = 0;
                if (!doc["ts"].get_int64().get(ts)) {
                    target_ts_ = ts;
                }
                is_history_ = true;
                return ControlAction::SwitchToHistory;
            }

            if (mode_sv == "live") {
                if (!is_history_) return ControlAction::None; // Уже в Live
                is_history_ = false;
                return ControlAction::SwitchToLive;
            }
        } catch (...) {
            // Игнорируем момент перезаписи файла фронтендом/бэкендом
        }
        return ControlAction::None;
    }

    [[nodiscard]] bool    is_history_mode() const noexcept { return is_history_; }
    [[nodiscard]] int64_t target_ts()       const noexcept { return target_ts_; }

private:
    std::filesystem::path            ctrl_path_;
    std::filesystem::file_time_type  last_mtime_{};
    bool                             is_history_ = false;
    int64_t                          target_ts_  = 0;
};
