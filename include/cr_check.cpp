
#pragma once
#include "cr_check.hpp"
uint32_t fletcher32(std::span<const std::byte> buf) noexcept
{
 uint32_t sum1 = 0xffff, sum2 = 0xffff;

    const uint16_t* data = reinterpret_cast<const uint16_t*>(buf.data());
    std::size_t len = buf.size_bytes() / 2;      // по 16-бит словам

    while (len) {
        std::size_t tlen = len > 360 ? 360 : len;   // 360 words per chunk
        len -= tlen;
        do {
            sum1 += *data++;
            sum2 += sum1;
        } while (--tlen);

        sum1 = (sum1 & 0xffff) + (sum1 >> 16);
        sum2 = (sum2 & 0xffff) + (sum2 >> 16);
    }
    /* final reduction */
    sum1 = (sum1 & 0xffff) + (sum1 >> 16);
    sum2 = (sum2 & 0xffff) + (sum2 >> 16);
    return (sum2 << 16) | sum1;
}
