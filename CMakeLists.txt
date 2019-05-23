cmake_minimum_required(VERSION 3.14)
project(broadcom_cfe_tool C)

set(CMAKE_C_STANDARD 11)

add_executable(broadcom_cfe_tool main.h main.c lzma/Alloc.c lzma/Alloc.h lzma/LzFind.c lzma/LzFind.h lzma/LzHash.h lzma/LzmaDec.c lzma/LzmaDec.h lzma/LzmaEnc.c lzma/LzmaEnc.h lzma/LzmaLib.c lzma/LzmaLib.h lzma/Types.h argtable/argtable3.h argtable/argtable3.c)
include_directories(lzma, argtable)