project(liblzma)
aux_source_directory(. DIR_LIB_SRCS)
add_library (lzma STATIC ${DIR_LIB_SRCS})