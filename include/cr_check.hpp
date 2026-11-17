//==============================================================
//  crc.hpp      –   Fletcher-32 контрольная сумма (заголовок)
//==============================================================
#pragma once
#include <cstdint>        // uint32_t
#include <cstddef>
#include <span>           // std::span  (C++20)

/* -------------------------------------------------------------
   compute_fletcher32

   Принимает непрерывный диапазон байтов (std::span<const std::byte>)
   и возвращает 32-битную контрольную сумму в формате:

        result = (sum2 << 16) | sum1

   • Алгоритм соответствует RFC 1145 / RFC 9055.
   • Функция не бросает исключений и не обращается к heap.
   • Оптимизированный SIMD-вариант реализован в crc.cpp.
   -------------------------------------------------------------*/
#include <simdjson.h>

inline bool fast_json_validate(const char* data, size_t len) noexcept
{
    simdjson::ondemand::parser p;
    auto result = p.iterate(data, len, /*realloc_if_needed*/ false);
    return !result.error();          // true → JSON цел
}
[[nodiscard]]
uint32_t fletcher32(std::span<const std::byte> data) noexcept;