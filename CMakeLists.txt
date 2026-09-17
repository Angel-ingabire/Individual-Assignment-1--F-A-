cmake_minimum_required(VERSION 3.20)
project(library_tracker C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)

add_executable(library_tracker src/main.c)
target_compile_options(library_tracker PRIVATE -Wall -Wextra -Wpedantic -O2)
target_link_libraries(library_tracker PRIVATE OpenSSL::Crypto)