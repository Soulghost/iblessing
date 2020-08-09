cmake_minimum_required(VERSION 3.5)

project(iblessing VERSION 1.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

add_executable(iblessing src/main.cpp)
target_link_libraries(iblessing "${CMAKE_SOURCE_DIR}/library/libcapstone.a")
target_include_directories(iblessing PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           "${CMAKE_SOURCE_DIR}/../submodules/unicorn/include"
                           "${CMAKE_SOURCE_DIR}/../submodules/capstone/include")

target_link_libraries(iblessing "${CMAKE_SOURCE_DIR}/library/libunicorn.a")