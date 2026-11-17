#include "graph_struct.hpp"
#include <cctype>

static inline int hex_val(char c) noexcept
{
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

ExecId make_exec_id(std::string_view hex) noexcept
{
    ExecId id{};                                   // заполнен нулями
    if (hex.size() != 64) return id;               // некорректная длина

    for (std::size_t i = 0; i < 32; ++i) {
        int hi = hex_val(hex[2*i]);
        int lo = hex_val(hex[2*i+1]);
        if (hi < 0 || lo < 0)                      // не hex-символ
            return ExecId{};                       // «пустой» id
        id[i] = static_cast<char>((hi << 4) | lo);
    }
    return id;
}