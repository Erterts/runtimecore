#pragma once
#include <atomic>
#include <csignal>

namespace shutdown {
    inline std::atomic<bool> running{true};
    inline void handler(int) noexcept {
        running.store(false, std::memory_order_relaxed);
    }
    inline void install() noexcept {
        std::signal(SIGINT,  handler);
        std::signal(SIGTERM, handler);
    }
}