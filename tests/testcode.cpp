
#define CATCH_CONFIG_MAIN

#include <catch2/catch.hpp>


#include "../src/main.cpp"

#include <sstream>
#include <iostream>


struct CoutRedirect {
    std::stringstream buffer;
    std::streambuf* old;
    std::ostream& target;

    explicit CoutRedirect(std::ostream& stream = std::cout)
        : old(stream.rdbuf(buffer.rdbuf())), target(stream) {}

    ~CoutRedirect() { target.rdbuf(old); }
};

// ====================================================================
// ТЕСТ-КЕЙСЫ (Названия на латинице для стабильности)
// ====================================================================

