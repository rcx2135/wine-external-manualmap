cmake_minimum_required(VERSION 3.16)

project(sncajector C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_EXTENSIONS ON)

add_library(ptrace_do STATIC
    lib/ptrace_do/libptrace_do.c
    lib/ptrace_do/parse_maps.c
)
add_compile_definitions(_GNU_SOURCE)

add_executable(injector
    src/main.c
)

target_link_libraries(injector ptrace_do)
