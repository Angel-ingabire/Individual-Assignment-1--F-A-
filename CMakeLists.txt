cmake_minimum_required(VERSION 3.20)
project(library_tracker C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)

set(TRACKER_MODULES
    src/types.h
    src/registry.inc
    src/blockchain.inc
    src/token_ledger.inc
    src/library_state.inc
    src/library_ops.inc
    src/cli.inc
    src/application.inc
)
set_source_files_properties(${TRACKER_MODULES} PROPERTIES HEADER_FILE_ONLY TRUE)

add_executable(library_tracker src/main.c ${TRACKER_MODULES})
target_compile_options(library_tracker PRIVATE -Wall -Wextra -Wpedantic -O2)
target_link_libraries(library_tracker PRIVATE OpenSSL::Crypto)