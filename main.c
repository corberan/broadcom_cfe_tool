#include <stdio.h>
#include <stdlib.h>
#include "main.h"
#include "lzma/LzmaLib.h"
#include "argtable3.h"

struct arg_lit *compress, *decompress, *help, *version;
struct arg_int *embed_nvram_offset, *embed_nvram_size;
struct arg_int *nvram_partition_space_size;
struct arg_file *input_file_path, *output_file_path;
struct arg_end *end;

unsigned char
hndcrc8(
        const unsigned char *pdata,    /* pointer to array of data to process */
        unsigned int nbytes,    /* number of input data bytes to process */
        unsigned char crc    /* either CRC8_INIT_VALUE or previous return value */
) {
    unsigned char result; // al
    unsigned int v4; // edx

    result = crc;
    if (nbytes) {
        v4 = 0;
        do {
            result = crc8_table[(unsigned char) (pdata[v4++] ^ result)];
        } while (v4 < nbytes);
    }
    return result;
}

const char *get_nvram_value(const char *nvram, size_t nvram_size, char *name) {
    char buff[READ_BUFFER_SIZE] = {0};
    size_t kv_loc = 0, kv_len = 0;
    do {
        const char *nvram_section = &nvram[kv_loc];
        kv_len = strnlen(nvram_section, nvram_size - kv_loc);
        if (kv_len > 0) {
            if (kv_len >= READ_BUFFER_SIZE) {
                fprintf(stderr, "Please increase the size of buff in get_nvram_value.\n");
                return NULL;
            }
            memset(buff, 0, READ_BUFFER_SIZE);
            if (strcpy_s(buff, READ_BUFFER_SIZE, nvram_section) != 0) {
                perror("Error while strcpy from nvram to buff in get_nvram_value.\n");
                exit(EXIT_FAILURE);
            }
            size_t buff_len = strnlen(buff, READ_BUFFER_SIZE);
            char *v4 = strchr(buff, 61); // ASC('=') == 61
            if (v4 != NULL && (size_t) (v4 - buff) < buff_len - 1) {
                *v4 = 0;
                int result = strcmp(name, buff);
                if (result == 0) {
                    return &nvram[kv_loc + (v4 - buff) + 1];
                }
            }
            kv_loc += kv_len;
        } else {
            kv_loc++;
        }
    } while (kv_loc < nvram_size);

    return NULL;
}

void explain_lzma_err(int ret) {
    char *err_msg = NULL;
    switch (ret) {
        case SZ_ERROR_DATA:
            err_msg = "LzmaCompress: Data error.";
            break;
        case SZ_ERROR_MEM:
            err_msg = "LzmaCompress: Memory allocation error.";
            break;
        case SZ_ERROR_UNSUPPORTED:
            err_msg = "LzmaCompress: Unsupported properties.";
            break;
        case SZ_ERROR_INPUT_EOF:
            err_msg = "LzmaCompress: It needs more bytes in input buffer (src).";
            break;
        default:
            err_msg = "LzmaCompress: Unknown error.";
            break;
    }
    fprintf(stderr, "%s\n", err_msg);
}

int compress_to_cfe(const char *nvram_text_file_path, const char *cfe_file_path, unsigned int output_offset,
                    unsigned int output_size) {
    FILE * fp_input;
    errno_t fopen_s_err_ret = fopen_s(&fp_input, nvram_text_file_path, "rb");
    if (fopen_s_err_ret != 0) {
        perror("Error while opening the input file.\n");
        exit(EXIT_FAILURE);
    }

    long input_file_size;
    fseek(fp_input, 0, SEEK_END);
    input_file_size = ftell(fp_input);
    rewind(fp_input);
    if (input_file_size < 1) {
        fprintf(stderr, "Input file is empty.\n");
        exit(EXIT_SUCCESS);
    }

    char *embed_nvram_uncompressed = NULL;
    size_t embed_nvram_uncompressed_size = sizeof(char) * (NVRAM_HEADER_SIZE + input_file_size);
    embed_nvram_uncompressed = (char *) malloc(embed_nvram_uncompressed_size);
    if (embed_nvram_uncompressed == NULL) {
        perror("Error while malloc for embed_nvram_uncompressed.\n");
        exit(EXIT_FAILURE);
    }
    memset(embed_nvram_uncompressed, 0, embed_nvram_uncompressed_size);

    char *embed_nvram_uncompressed_end = &embed_nvram_uncompressed[NVRAM_HEADER_SIZE];
    char read_buffer[READ_BUFFER_SIZE] = {0};
    while (fgets(read_buffer, READ_BUFFER_SIZE, fp_input) != NULL) {
        size_t line_len = strlen(read_buffer);
        if (line_len > 0 && read_buffer[0] != 35) { // ASC('#') == 35
            for (unsigned int i = 0; i < line_len; i++) {
                if (read_buffer[i] == 10 || read_buffer[i] == 13) { // LF 10 CR 13
                    if (i != 0) {
                        embed_nvram_uncompressed_end++;
                    }
                    break;
                }
                *embed_nvram_uncompressed_end = read_buffer[i];
                embed_nvram_uncompressed_end++;
            }
        }
    }

    // get sdram_init, sdram_config, sdram_refresh, sdram_ncdl for nvram_header
    const char *nvram_for_search = &embed_nvram_uncompressed[NVRAM_HEADER_SIZE];
    size_t nvram_for_search_size = embed_nvram_uncompressed_size - NVRAM_HEADER_SIZE;

    unsigned long sdram_init = 0, sdram_config = 0, sdram_refresh = 0, sdram_ncdl = 0;
    const char *nvram_value = get_nvram_value(nvram_for_search, nvram_for_search_size, "sdram_init");
    if (nvram_value != NULL) {
        sdram_init = strtoul(nvram_value, NULL, 0);
    }
    if ((nvram_value = get_nvram_value(nvram_for_search, nvram_for_search_size, "sdram_config")) != NULL) {
        sdram_config = strtoul(nvram_value, NULL, 0);
    }
    if ((nvram_value = get_nvram_value(nvram_for_search, nvram_for_search_size, "sdram_refresh")) != NULL) {
        sdram_refresh = strtoul(nvram_value, NULL, 0);
    }
    if ((nvram_value = get_nvram_value(nvram_for_search, nvram_for_search_size, "sdram_ncdl")) != NULL) {
        sdram_ncdl = strtoul(nvram_value, NULL, 0);
    }
//    printf("%ld, %ld, %ld, %ld\n", sdram_init, sdram_config, sdram_refresh, sdram_ncdl);

    NVRAM_HEADER *embed_nvram_header = NULL;
    embed_nvram_header = (NVRAM_HEADER *) &embed_nvram_uncompressed[0];

    embed_nvram_header->magic = NVRAM_MAGIC;
    embed_nvram_header->len =
            ((size_t) (embed_nvram_uncompressed_end - embed_nvram_uncompressed) + 4) & 0xFFFFFFFC; // ROUNDUP(,4),
    embed_nvram_header->crc_ver_init = (NVRAM_VERSION << 8u) | ((sdram_init & 0xffffu) << 16u);
    embed_nvram_header->config_refresh = (sdram_config & 0xffffu) | ((sdram_refresh & 0xffffu) << 16u);
    embed_nvram_header->crc_ver_init |= hndcrc8((unsigned char *) &embed_nvram_uncompressed[9],
                                                embed_nvram_header->len - 9,
                                                CRC8_INIT_VALUE);
    embed_nvram_header->config_ncdl = sdram_ncdl;

    char *embed_nvram_compressed = NULL;
    size_t embed_nvram_compressed_size = sizeof(char) * DEF_EMBED_NVRAM_SIZE;
    embed_nvram_compressed = (char *) malloc(embed_nvram_compressed_size);
    if (embed_nvram_compressed == NULL) {
        perror("Error while malloc for embed_nvram_compressed.\n");
        exit(EXIT_FAILURE);
    }
    memset(embed_nvram_compressed, 0, embed_nvram_compressed_size);

    for (size_t i = 0; i < NVRAM_HEADER_SIZE && i < embed_nvram_compressed_size; i++) {
        embed_nvram_compressed[i] = embed_nvram_uncompressed[i];
    }

    size_t output_props_size = LZMA_PROPS_SIZE;
    size_t dest_len = embed_nvram_compressed_size - NVRAM_HEADER_SIZE;
    size_t src_len = embed_nvram_header->len;

    int ret = LzmaCompress(
            (unsigned char *) &embed_nvram_compressed[NVRAM_HEADER_SIZE + LZMA_PROPS_SIZE],
            &dest_len,
            (const unsigned char *) &embed_nvram_uncompressed[NVRAM_HEADER_SIZE],
            src_len - NVRAM_HEADER_SIZE,
            (unsigned char *) &embed_nvram_compressed[NVRAM_HEADER_SIZE],
            &output_props_size,
            -1,
            0x10000u,
            -1,
            -1,
            -1,
            -1,
            -1);

    if (ret != SZ_OK) {
        explain_lzma_err(ret);
        exit(EXIT_SUCCESS);
    }

    FILE * fp_output;
    fopen_s_err_ret = fopen_s(&fp_output, cfe_file_path, "r+b");
    if (fopen_s_err_ret != 0) {
        perror("Error while opening the output file.\n");
        exit(EXIT_FAILURE);
    }
    fseek(fp_output, output_offset, SEEK_SET);
    fwrite(embed_nvram_compressed, sizeof(char), output_size, fp_output);

    free(embed_nvram_compressed);
    free(embed_nvram_uncompressed);

    fclose(fp_output);
    fclose(fp_input);
    return 0;
}

int decompress_from_cfe(const char *cfe_file_path, const char *nvram_text_file_path, unsigned int read_offset,
                        unsigned int read_count, unsigned int nvram_partition_size) {
    FILE * fp_input;
    errno_t fopen_s_err_ret = fopen_s(&fp_input, cfe_file_path, "rb");
    if (fopen_s_err_ret != 0) {
        perror("Error while opening the input file.\n");
        exit(EXIT_FAILURE);
    }

    long input_file_size;
    fseek(fp_input, 0, SEEK_END);
    input_file_size = ftell(fp_input);
    rewind(fp_input);
    if (input_file_size < 1) {
        fprintf(stderr, "Input file is empty.\n");
        exit(EXIT_SUCCESS);
    }

    if (fseek(fp_input, read_offset, SEEK_SET) != 0) {
        fprintf(stderr, "Wrong offset %d, larger than file size %ld.\n", read_offset, input_file_size);
        exit(EXIT_SUCCESS);
    }

    char *embed_nvram_compressed = NULL;
    size_t embed_nvram_compressed_size = sizeof(char) * DEF_EMBED_NVRAM_SIZE;
    embed_nvram_compressed = (char *) malloc(embed_nvram_compressed_size);
    if (embed_nvram_compressed == NULL) {
        perror("Error while malloc for embed_nvram_compressed.\n");
        exit(EXIT_FAILURE);
    }
    memset(embed_nvram_compressed, 0, embed_nvram_compressed_size);

    size_t num_read = fread_s(embed_nvram_compressed, embed_nvram_compressed_size, sizeof(char), read_count, fp_input);
    if (num_read != read_count) {
        fprintf(stderr, "Expected reading size is %d, but the actual number of reads is %d.\n",
                sizeof(char) * read_count, num_read);
        exit(EXIT_SUCCESS);
    }

    char *embed_nvram_uncompressed = NULL;
    size_t embed_nvram_uncompressed_size = sizeof(char) * nvram_partition_size;
    embed_nvram_uncompressed = (char *) malloc(embed_nvram_uncompressed_size);
    if (embed_nvram_uncompressed == NULL) {
        perror("Error while malloc for embed_nvram_uncompressed.\n");
        exit(EXIT_FAILURE);
    }
    memset(embed_nvram_uncompressed, 0, embed_nvram_uncompressed_size);

    size_t outPropsSize = LZMA_PROPS_SIZE;
    size_t destLen = embed_nvram_uncompressed_size;
    size_t srcLen = embed_nvram_compressed_size - NVRAM_HEADER_SIZE - LZMA_PROPS_SIZE;

    int ret = LzmaUncompress(
            (unsigned char *) &embed_nvram_uncompressed[0],
            &destLen,
            (const unsigned char *) &embed_nvram_compressed[NVRAM_HEADER_SIZE + LZMA_PROPS_SIZE],
            &srcLen,
            (const unsigned char *) &embed_nvram_compressed[NVRAM_HEADER_SIZE],
            outPropsSize);

    if (ret != SZ_OK) {
        explain_lzma_err(ret);
        exit(EXIT_SUCCESS);
    }

    for (size_t i = 0; i < destLen && i < embed_nvram_uncompressed_size; i++) {
        if (embed_nvram_uncompressed[i] == 0) {
            embed_nvram_uncompressed[i] = 10;
        }
    }

    FILE * fp_output;
    fopen_s_err_ret = fopen_s(&fp_output, nvram_text_file_path, "wb");
    if (fopen_s_err_ret != 0) {
        perror("Error while opening the output file.\n");
        exit(EXIT_FAILURE);
    }
    fwrite(embed_nvram_uncompressed, sizeof(char), destLen, fp_output);

    free(embed_nvram_uncompressed);
    free(embed_nvram_compressed);

    fclose(fp_input);
    fclose(fp_output);

    return 0;
}

int main(int argc, char *argv[]) {
    void *argtable[] = {
            help = arg_litn("h", "help", 0, 1, "display this help and exit"),
            version = arg_litn("v", "version", 0, 1, "display version info and exit"),
            compress = arg_litn("z", "compress", 0, 1, "compress NVRAM data to CFE file"),
            decompress = arg_litn("d", "decompress", 0, 1, "decompress embedded NVRAM data from CFE file"),
            embed_nvram_offset = arg_intn("b", "offset", "<n>", 0, 1,
                                          "offset within output to embed NVRAM (default 0x400)"),
            embed_nvram_size = arg_intn("c", "count", "<n>", 0, 1, "bytes of embed NVRAM to write (default 0x1000)"),
            nvram_partition_space_size = arg_intn(NULL, "nvram_space", "<n>", 0, 1,
                                                  "size of the NVRAM partition space (default 0x10000)"),
            input_file_path = arg_file1("i", "input", "<file>", "input file"),
            output_file_path = arg_file1("o", "output", "<file>", "output file"),
            end = arg_end(20),
    };

    int exit_code = 0;
    char program_name[] = "broadcom_cfe_tool.exe";

    int n_errors;
    n_errors = arg_parse(argc, argv, argtable);

    if (version->count > 0) {
        printf("Broadcom CFE tool v0.1.0\n");
        printf("Copyright 2019 spoon\n");
        exit_code = 0;
        goto exit;
    }

    if (help->count > 0) {
        printf("Usage: %s", program_name);
        arg_print_syntax(stdout, argtable, "\n");
        printf("Compress/decompress embedded NVRAM data to/from Broadcom CFE (boot loader) file.\n\n");
        arg_print_glossary(stdout, argtable, "  %-25s %s\n");
        exit_code = 0;
        goto exit;
    }

    if (n_errors > 0) {
        /* Display the error details contained in the arg_end struct.*/
        arg_print_errors(stdout, end, program_name);
        printf("Try '%s --help' for more information.\n", program_name);
        exit_code = 1;
        goto exit;
    }

    unsigned int offset = DEF_EMBED_NVRAM_OFFSET, size = DEF_EMBED_NVRAM_SIZE, space = DEF_NVRAM_PARTITION_SPACE;
    if (embed_nvram_offset->count > 0 && *embed_nvram_offset->ival > 0) {
        offset = *embed_nvram_offset->ival;
    }
    if (embed_nvram_size->count > 0 && *embed_nvram_size->ival > 0) {
        size = *embed_nvram_size->ival;
    }
    if (nvram_partition_space_size->count > 0 && *nvram_partition_space_size->ival > 0) {
        space = *nvram_partition_space_size->ival;
    }

    if (compress->count > 0 && decompress->count == 0) {
        // size - 4 comes from nvserial_6.x.4708 line 719
        exit_code = compress_to_cfe(*input_file_path->filename, *output_file_path->filename, offset, size - 4);
    } else if (decompress->count > 0 && compress->count == 0) {
        exit_code = decompress_from_cfe(*input_file_path->filename, *output_file_path->filename, offset, size - 4,
                                        space);
    } else {
        printf("Try '%s --help' for more information.\n", program_name);
        exit_code = 1;
        goto exit;
    }

    exit:
    /* deallocate each non-null entry in argtable[] */
    arg_freetable(argtable, sizeof(argtable) / sizeof(argtable[0]));
    return exit_code;
}