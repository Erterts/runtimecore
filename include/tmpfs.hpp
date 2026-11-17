#pragma once
#include <string>
void   init_io_paths();                         // вызываем один раз в main
std::string read_raw();                         // вернуть одну JSON-строку или ""
void   write_to_tmpfs(const char* dst, const std::string& data);