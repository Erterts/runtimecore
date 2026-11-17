cmake_minimum_required(VERSION 3.15)
project(runtimecore CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Разрешаем CMake 4+ собирать старые зависимости вроде RapidJSON v1.1.0
set(CMAKE_POLICY_VERSION_MINIMUM 3.10)

include(FetchContent)

set(BOOST_ENABLE_CMAKE ON)
set(BOOST_INCLUDE_LIBRARIES unordered)

FetchContent_Declare(
    Boost
    URL https://github.com/boostorg/boost/releases/download/boost-1.92.0/boost-1.92.0-cmake.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)


FetchContent_Declare(
    simdjson
    URL https://github.com/simdjson/simdjson/archive/refs/tags/v5.1.1.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_Declare(
    rapidjson
    URL https://github.com/Tencent/rapidjson/archive/refs/tags/v1.1.0.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    SOURCE_SUBDIR non_existent_dir
)



FetchContent_MakeAvailable(Boost simdjson rapidjson)

add_executable(${PROJECT_NAME} 
    src/main.cpp
    include/cr_check.cpp
)

# Подключаем вашу папку include и заголовки скачанного rapidjson
target_include_directories(${PROJECT_NAME} PRIVATE 
    include
    ${rapidjson_SOURCE_DIR}/include
)

# Убираем rapidjson из target_link_libraries, так как он подключен как header-only выше
target_link_libraries(${PROJECT_NAME} PRIVATE 
    Boost::unordered 
    simdjson
)

if(UNIX AND NOT APPLE)
    target_link_options(${PROJECT_NAME} PRIVATE -static-libgcc -static-libstdc++)
endif()
