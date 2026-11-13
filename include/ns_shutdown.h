#pragma once
#include <atomic>
#include <csignal>
#include <condition_variable>

namespace shutdown {

    /*  Глобальный флаг «живём / завершаемся».
        atomic<bool> безопасен в обработчике сигналов.          */
    inline std::atomic<bool> running{true};

    /*  Указатель на condition_variable очереди.
        Чтобы «разбудить» heavy-thread, когда пришёл SIGINT.    */
    inline std::condition_variable* cv_ptr = nullptr;

    /*  Обработчик сигнала  ------------------------------------*/
    inline void handler(int) noexcept
    {
        running.store(false, std::memory_order_relaxed);
        if (cv_ptr)  cv_ptr->notify_all();      // разблокировать wait()
    }

    /*  Регистрация (вызывать из main перед запуском потоков)   */
    inline void install(std::condition_variable& cv) noexcept
    {
        cv_ptr = &cv;
        std::signal(SIGINT,  handler);   //  Ctrl-C
        std::signal(SIGTERM, handler);   //  docker stop / kill -15
    }
}