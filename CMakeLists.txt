cmake_minimum_required(VERSION 3.14)

project(LTracer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/utils
)

add_executable(LTracer
        src/main.cpp
        utils/SyscallMap.cpp
)