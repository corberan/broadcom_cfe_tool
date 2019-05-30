cmake_minimum_required(VERSION 3.14)
project(broadcom_cfe_tool C)

set(CMAKE_C_STANDARD 11)

aux_source_directory(. DIR_SRCS)
add_subdirectory(lzma)
add_subdirectory(argtable)

add_executable(broadcom_cfe_tool main.c)
target_link_libraries(broadcom_cfe_tool lzma argtable)