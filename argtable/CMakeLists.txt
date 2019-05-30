project(libargtable)
aux_source_directory(. DIR_LIB_SRCS)
add_library (argtable STATIC ${DIR_LIB_SRCS})