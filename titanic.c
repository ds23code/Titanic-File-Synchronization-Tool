// A file synchronisation tool that processes:
//      file differences,
//      block comparison (using hash), 
//      and apply updates.

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "titanic.h"

// Function Prototypes
// Stage 1 (Helper)
static void write_tabi_header(FILE *output_file, size_t num_in_pathnames);
static void write_pathname_info(FILE *output_file, char *path_name);
static void write_block_count(FILE *output_file, int blocks_counter);
static void process_file_blocks(FILE *output_file, 
    char *path_name, int blocks_counter);
static void process_single_file(FILE *output_file, char *path_name);
// Stage 1
void stage_1(char *out_pathname, char *in_pathnames[], size_t num_in_pathnames);
// Stage 2 (Helper)
static uint16_t read_pathname_from_file(FILE *input_file, char *pathname);
static uint32_t read_block_count_from_file(FILE *input_file);
static uint64_t *read_hashes_from_file(FILE *input_file, 
    uint32_t blocks_counter);
static void compare_local_blocks(const char *pathname, uint64_t *hashes, 
    uint32_t blocks_counter, uint8_t *matches);
static void check_record(FILE *input_file, FILE *output_file);
static void write_tbbi_header(FILE *input_file, FILE *output_file);
// Stage 2
void stage_2(char *out_pathname, char *in_pathname);
// Stage 3 (Helper)
static uint32_t count_updates_needed(uint8_t *matches, uint32_t blocks_counter);
static void write_file_permissions(FILE *output_file, mode_t st_mode);
static void write_tcbi_record_header(FILE *output_file, const char *pathname, 
    uint16_t path_length, struct stat *st, uint32_t updates);
static void write_update_data(FILE *output_file, const char *pathname, 
    uint8_t *matches, uint32_t blocks_counter, uint32_t updates);
static void tbbi_record(FILE *input_file, FILE *output_file);
static void write_tcbi_header(FILE *input_file, FILE *output_file);
// Stage 3
void stage_3(char *out_pathname, char *in_pathname);
// Stage 4 (Helper)
static bool check_path(const char *path);
static mode_t file_permissions(const char *perms);
static void read_tcbi_header(FILE *tcbifile);
static char *read_tcbi_pathname(FILE *tcbifile);
static void read_file_metadata(FILE *tcbifile, char *mode_str, 
    uint32_t *file_size, uint32_t *num_updates);
static void handle_directory(const char *pathname, const char *mode_str);
static void apply_file_update(FILE *tcbifile, int regular_file);
static void handle_regular_file(FILE *tcbifile, const char *pathname, 
    const char *mode_str, uint32_t file_size, uint32_t num_updates);
// Stage 4
void stage_4(char *in_pathname); 

// Helper function to write TABI magic header
static void write_tabi_header(FILE *output_file, size_t num_in_pathnames) {
    fputc('T', output_file);
    fputc('A', output_file);
    fputc('B', output_file);
    fputc('I', output_file);
    fputc((int)(num_in_pathnames & 0xFF), output_file);
}

// Helper function to write pathname info to TABI file
static void write_pathname_info(FILE *output_file, char *path_name) {
    uint16_t path_length = strlen(path_name);
    fputc(path_length & 0xFF, output_file);    
    fputc((path_length >> 8) & 0xFF, output_file);
    fwrite(path_name, 1, path_length, output_file);
}

// Helper function to write block count to TABI file
static void write_block_count(FILE *output_file, int blocks_counter) {
    for (int j = 0; j <= 2; j++) {
        fputc((blocks_counter >> (8 * j)) & 0xFF, output_file);
    }
}

// Helper function to process file blocks and write hashes
static void process_file_blocks(FILE *output_file, char *path_name, 
    int blocks_counter) {
    FILE *input_file = fopen(path_name, "rb");
    if (input_file == NULL) {
        fprintf(stderr, "Error!!! (in opening input_file)");
        exit(1);
    }
    
    for (int block_index = 0; block_index < blocks_counter; block_index++) {
        char blocks_array[BLOCK_SIZE];
        size_t block_bytes = fread(blocks_array, 1, BLOCK_SIZE, input_file);
        if (ferror(input_file)) {
            fprintf(stderr, "Error!!! (in compute hash)");
            exit(1);
        }
        uint64_t hash = hash_block(blocks_array, block_bytes);
        // Write 8-byte hash in little-endian
        for (int k = 0; k < 8; k++) {
            fputc((hash >> (8 * k)) & 0xFF, output_file);
        }
    }
    fclose(input_file);
}

// Helper function to process single file for TABI creation
static void process_single_file(FILE *output_file, char *path_name) {
    write_pathname_info(output_file, path_name);
    
    struct stat file_size;
    if (stat(path_name, &file_size) != 0) {
        fprintf(stderr, "Error!!! (in file size)");
        exit(1);
    }
    
    int blocks_counter = number_of_blocks_in_file(file_size.st_size);
    write_block_count(output_file, blocks_counter);
    process_file_blocks(output_file, path_name, blocks_counter);
}

/// @brief Create a TABI file from an array of pathnames.
/// @param out_pathname A path to where the new TABI file should be created.
/// @param in_pathnames An array of strings containing, in order, the files
//                      that should be placed in the new TABI file.
/// @param num_in_pathnames The length of the `in_pathnames` array. In
///                         subset 5, when this is zero, you should include
///                         everything in the current directory.
void stage_1(char *out_pathname, char *in_pathnames[], 
    size_t num_in_pathnames) {    
    FILE *output_file = fopen(out_pathname, "wb");
    write_tabi_header(output_file, num_in_pathnames);
    
    for (size_t i = 0; i < num_in_pathnames; i++) {
        process_single_file(output_file, in_pathnames[i]);
    }
    fclose(output_file);
}

// Helper function to read pathname from input file
static uint16_t read_pathname_from_file(FILE *input_file, char *pathname) {
    uint16_t path_length;
    if (fread(&path_length, 2, 1, input_file) != 1 ||
        path_length > PATH_MAX || 
        fread(pathname, 1, path_length, input_file) != path_length) {
        fprintf(stderr, "Error!!! (in path length)");
        exit(1);
    }
    pathname[path_length] = '\0';
    return path_length;
}

// Helper function to read block count from input file
static uint32_t read_block_count_from_file(FILE *input_file) {
    uint8_t block_bytes[3];
    if (fread(block_bytes, 1, 3, input_file) != 3) {
        fprintf(stderr, "Error!!! (in number of blocks)");
        exit(1);
    }
    return block_bytes[0] | (block_bytes[1] << 8) | (block_bytes[2] << 16);
}

// Helper function to read hashes from input file
static uint64_t *read_hashes_from_file(FILE *input_file,
    uint32_t blocks_counter) {
    uint64_t *hashes = malloc(blocks_counter * sizeof(uint64_t));
    if (hashes == NULL) {
        fprintf(stderr, "Error!!! (in malloc)");
        exit(1);
    }
    
    for (uint32_t block = 0; block < blocks_counter; block++) {
        uint64_t hash = 0;
        for (int byte = 0; byte < 8; byte++) {
            int c = fgetc(input_file);
            if (c == EOF) {
                fprintf(stderr, "Error!!! (in read hash)");
                free(hashes);
                exit(1);
            }
            hash |= (uint64_t)c << (byte * 8);
        }
        hashes[block] = hash;
    }
    return hashes;
}

// Helper function to compare local file blocks with hashes
static void compare_local_blocks(const char *pathname, uint64_t *hashes, 
                                uint32_t blocks_counter, uint8_t *matches) {
    struct stat st;
    if (stat(pathname, &st)) {
        if (errno != ENOENT) {
            fprintf(stderr, "Error!!! (in pathname)");
            exit(1);
        }
    } else if (S_ISREG(st.st_mode)) {
        FILE *local_file = fopen(pathname, "rb");
        if (local_file) {
            for (uint32_t block = 0; block < blocks_counter; block++) {
                char buffer[BLOCK_SIZE];
                size_t bytes_read = fread(buffer, 1, BLOCK_SIZE, local_file);
                if (bytes_read == 0) break;
                uint64_t local_hash = hash_block(buffer, bytes_read);
                if (local_hash == hashes[block]) {
                    size_t byte_index = block / 8;
                    uint8_t bit_index = block % 8;
                    matches[byte_index] |= (1 << (7 - bit_index));
                }
            }
            fclose(local_file);
        }
    }
}

// Reads record from input_file, compares hashe, writes result to output_file
static void check_record(FILE *input_file, FILE *output_file) {
    char pathname[PATH_MAX];
    uint16_t path_length = read_pathname_from_file(input_file, pathname);
    
    fwrite(&path_length, 2, 1, output_file);
    fwrite(pathname, 1, path_length, output_file);
    
    uint32_t blocks_counter = read_block_count_from_file(input_file);
    uint8_t block_bytes[3] = {blocks_counter & 0xFF, 
        (blocks_counter >> 8) & 0xFF, (blocks_counter >> 16) & 0xFF};
    fwrite(block_bytes, 1, 3, output_file);
    
    uint64_t *hashes = read_hashes_from_file(input_file, blocks_counter);
    
    size_t num_match_bytes = num_tbbi_match_bytes(blocks_counter);
    uint8_t *matches = calloc(num_match_bytes, 1);
    if (matches == NULL) {
        fprintf(stderr, "Error!!! (in calloc)");
        free(hashes);
        exit(1);
    }
    
    compare_local_blocks(pathname, hashes, blocks_counter, matches);
    
    fwrite(matches, 1, num_match_bytes, output_file);
    free(hashes);
    free(matches);
}

// Helper function to write TBBI header
static void write_tbbi_header(FILE *input_file, FILE *output_file) {
    char magic[4];
    if (fread(magic, 1, 4, input_file) != 4 || memcmp(magic, "TABI", 4) != 0) {
        fprintf(stderr, "Error!!! (in TABI)");
        exit(1);
    }
    fputc('T', output_file);
    fputc('B', output_file);
    fputc('B', output_file);
    fputc('I', output_file);
}

/// @brief Create a TBBI file from a TABI file.
/// @param out_pathname A path to where the new TBBI file should be created.
/// @param in_pathname A path to where the existing TABI file is located.
void stage_2(char *out_pathname, char *in_pathname) {
    FILE *input_file = fopen(in_pathname, "rb");
    FILE *output_file = fopen(out_pathname, "wb");
    if (input_file == NULL || output_file == NULL) {
        fprintf(stderr, "Error!!! (in file opening)");
        exit(1);
    }
    
    write_tbbi_header(input_file, output_file);

    int num_records_byte = fgetc(input_file);
    unsigned num_records = num_records_byte;
    if (num_records_byte == EOF || num_records == 0) {
        fprintf(stderr, "Error!!! (in incomplete TABI file)");
        exit(1);
    }
    fputc(num_records, output_file);
    
    for (unsigned record = 0; record < num_records; record++) {
        check_record(input_file, output_file);
    }
    if (fgetc(input_file) != EOF) {
        fprintf(stderr, "Error!!! (in records)");
        exit(1);
    }
    fclose(input_file);
    fclose(output_file);
}

// Helper function to count blocks needing updates
static uint32_t count_updates_needed(uint8_t *matches, 
    uint32_t blocks_counter) {
    uint32_t updates = 0;
    for (uint32_t block = 0; block < blocks_counter; block++) {
        size_t byte_index = block / 8;
        uint8_t bit_index = block % 8;
        uint8_t bit_mask = 1 << (7 - bit_index);
        if ((matches[byte_index] & bit_mask) == 0) {
            updates++;
        }
    }
    return updates;
}

// Helper function to write file permissions
static void write_file_permissions(FILE *output_file, mode_t st_mode) {
    char perms[9];
    perms[0] = (st_mode & S_IRUSR) ? 'r' : '-';
    perms[1] = (st_mode & S_IWUSR) ? 'w' : '-';
    perms[2] = (st_mode & S_IXUSR) ? 'x' : '-';
    perms[3] = (st_mode & S_IRGRP) ? 'r' : '-';
    perms[4] = (st_mode & S_IWGRP) ? 'w' : '-';
    perms[5] = (st_mode & S_IXGRP) ? 'x' : '-';
    perms[6] = (st_mode & S_IROTH) ? 'r' : '-';
    perms[7] = (st_mode & S_IWOTH) ? 'w' : '-';
    perms[8] = (st_mode & S_IXOTH) ? 'x' : '-';
    fwrite(perms, 1, 9, output_file);
}

// Helper function to write TCBI record header
static void write_tcbi_record_header(FILE *output_file, const char *pathname, 
                                   uint16_t path_length, 
                                   struct stat *st, uint32_t updates) {
    fwrite(&path_length, 2, 1, output_file);
    fwrite(pathname, 1, path_length, output_file);
    
    char file_type = 
    S_ISREG(st->st_mode) ? '-' : S_ISDIR(st->st_mode) ? 'd' : '?';
    fputc(file_type, output_file);
    
    write_file_permissions(output_file, st->st_mode);
    
    uint32_t file_size = st->st_size;
    for (int i = 0; i < 4; i++) {
        fputc((file_size >> (8 * i)) & 0xFF, output_file);
    }
    
    for (int i = 0; i < 3; i++) {
        fputc((updates >> (8 * i)) & 0xFF, output_file);
    }
}

// Helper function to write update data for blocks
static void write_update_data(FILE *output_file, const char *pathname, 
                             uint8_t *matches, 
                             uint32_t blocks_counter, uint32_t updates) {
    if (updates > 0) {
        FILE *local_file = fopen(pathname, "rb");
        if (local_file == NULL) {
            fprintf(stderr, "Error!!! (in opening local file)");
            free(matches);
            exit(1);
        }
        for (uint32_t block = 0; block < blocks_counter; block++) {
            if (matches[block/8] & (1 << (7 - block%8))) continue;
            for (int i = 0; i < 3; i++) fputc(block >> (i*8), output_file);
            if (fseek(local_file, block * BLOCK_SIZE, SEEK_SET)) {
                fprintf(stderr, "Error!!! (in fseek)");
                fclose(local_file);
                free(matches);
                exit(1);
            }
            char data[BLOCK_SIZE];
            size_t n = fread(data, 1, BLOCK_SIZE, local_file);
            if (ferror(local_file)) {
                fprintf(stderr, "Error!!! (in block read)");
                fclose(local_file);
                free(matches);
                exit(1);
            }
            fputc(n, output_file);
            fputc(n >> 8, output_file);
            fwrite(data, 1, n, output_file);
        }
        fclose(local_file);
    }
}

// Helper function for STAGE 3
// Process a single TBBI record and write corresponding TCBI record
static void tbbi_record(FILE *input_file, FILE *output_file) {
    char pathname[PATH_MAX];
    uint16_t path_length = read_pathname_from_file(input_file, pathname);
    uint32_t blocks_counter = read_block_count_from_file(input_file);
    
    size_t num_match_bytes = num_tbbi_match_bytes(blocks_counter);
    uint8_t *matches = malloc(num_match_bytes);
    if (matches == NULL) {
        fprintf(stderr, "Error!!! (in malloc)");
        exit(1);
    }
    if (fread(matches, 1, num_match_bytes, input_file) != num_match_bytes) {
        fprintf(stderr, "Error!!! (in read matches)");
        free(matches);
        exit(1);
    }
    
    uint32_t updates = count_updates_needed(matches, blocks_counter);
    
    struct stat st;
    if (stat(pathname, &st) != 0) {
        fprintf(stderr, "Error!!! (in stat)");
        free(matches);
        exit(1);
    }
    
    write_tcbi_record_header(output_file, pathname, path_length, &st, updates);
    write_update_data(output_file, pathname, matches, blocks_counter, updates);
    
    free(matches);
}

// Helper function to write TCBI header
static void write_tcbi_header(FILE *input_file, FILE *output_file) {
    char magic[4];
    if (fread(magic, 1, 4, input_file) != 4 || memcmp(magic, "TBBI", 4) != 0) {
        fprintf(stderr, "Error!!! (in TBBI)");
        exit(1);
    }
    fputc('T', output_file);
    fputc('C', output_file);
    fputc('B', output_file);
    fputc('I', output_file);
}

/// @brief Create a TCBI file from a TBBI file.
/// @param out_pathname A path to where the new TCBI file should be created.
/// @param in_pathname A path to where the existing TBBI file is located.
void stage_3(char *out_pathname, char *in_pathname) {
    FILE *input_file = fopen(in_pathname, "rb");
    FILE *output_file = fopen(out_pathname, "wb");
    if (input_file == NULL || output_file == NULL) {
        fprintf(stderr, "Error!!! (in file opening)");
        exit(1);
    }
    
    write_tcbi_header(input_file, output_file);
    
    int num_records_byte = fgetc(input_file);
    unsigned num_records = num_records_byte;
    if (num_records_byte == EOF || num_records == 0) {
        fprintf(stderr, "Error!!! (in incomplete TBBI file)");
        exit(1);
    }
    fputc(num_records, output_file);
    
    for (unsigned record = 0; record < num_records; record++) {
        tbbi_record(input_file, output_file);
    }
    
    if (fgetc(input_file) != EOF) {
        fprintf(stderr, "Error!!! (in records)");
        exit(1);
    }
    fclose(input_file);
    fclose(output_file);
}

// Helper function to check if a path is safe
static bool check_path(const char *path) {
    if (path[0] == '/') {
        return false;
    }
    char *copy = strdup(path);
    if (copy == NULL) {
        perror("Error!!! (in strdup)");
        exit(1);
    }
    int depth = 0;
    char *saveptr = NULL;
    char *token = strtok_r(copy, "/", &saveptr);
    while (token != NULL) {
        if (strcmp(token, ".") == 0) {
        // Skip current directory
        } else if (strcmp(token, "..") == 0) {
            if (depth > 0) {
                depth--;
            } else {
                free(copy);
                return false;
            }
        } else {
            depth++;
        }
        token = strtok_r(NULL, "/", &saveptr);
    }
    free(copy);
    return true;
}

// Helper function to convert permission string to mode_t
static mode_t file_permissions(const char *perms) {
    mode_t mode = 0;
    if (perms[0] == 'r') mode |= S_IRUSR;
    if (perms[1] == 'w') mode |= S_IWUSR;
    if (perms[2] == 'x') mode |= S_IXUSR;
    if (perms[3] == 'r') mode |= S_IRGRP;
    if (perms[4] == 'w') mode |= S_IWGRP;
    if (perms[5] == 'x') mode |= S_IXGRP;
    if (perms[6] == 'r') mode |= S_IROTH;
    if (perms[7] == 'w') mode |= S_IWOTH;
    if (perms[8] == 'x') mode |= S_IXOTH;
    return mode;
}

// Helper function to read TCBI header and validate
static void read_tcbi_header(FILE *tcbifile) {
    char magic[4];
    if (fread(magic, 1, 4, tcbifile) != 4 || memcmp(magic, "TCBI", 4) != 0) {
        fprintf(stderr, "Error!!! (invalid TCBI file)");
        exit(1);
    }
}

// Helper function to read pathname from TCBI file
static char *read_tcbi_pathname(FILE *tcbifile) {
    uint8_t len_bytes[2];
    if (fread(len_bytes, 1, 2, tcbifile) != 2) {
        fprintf(stderr, "Error!!! (in pathname length)");
        exit(1);
    }
    uint16_t pathname_len = len_bytes[0] | (len_bytes[1] << 8);
    
    char *pathname = malloc(pathname_len + 1);
    if (pathname == NULL) {
        perror("Error!!! (in malloc)");
        exit(1);
    }
    if (fread(pathname, 1, pathname_len, tcbifile) != pathname_len) {
        fprintf(stderr, "Error!!! (in reading pathname)");
        free(pathname);
        exit(1);
    }
    pathname[pathname_len] = '\0';
    return pathname;
}

// Helper function to read file metadata from TCBI
static void read_file_metadata(FILE *tcbifile, char *mode_str, 
    uint32_t *file_size, uint32_t *num_updates) {
    if (fread(mode_str, 1, 10, tcbifile) != 10) {
        fprintf(stderr, "Error!!! (in mode string)");
        exit(1);
    }
    mode_str[10] = '\0';
    
    uint8_t size_bytes[4];
    if (fread(size_bytes, 1, 4, tcbifile) != 4) {
        fprintf(stderr, "Error!!! (in file size)");
        exit(1);
    }
    *file_size = (uint32_t)size_bytes[0] | 
                ((uint32_t)size_bytes[1] << 8) | 
                ((uint32_t)size_bytes[2] << 16) | 
                ((uint32_t)size_bytes[3] << 24);

    uint8_t num_updates_bytes[3];
    if (fread(num_updates_bytes, 1, 3, tcbifile) != 3) {
        fprintf(stderr, "Error!!! (in updates)");
        exit(1);
    }
    *num_updates = (uint32_t)num_updates_bytes[0] | 
                   ((uint32_t)num_updates_bytes[1] << 8) | 
                   ((uint32_t)num_updates_bytes[2] << 16);
}

// Helper function to handle directory creation
static void handle_directory(const char *pathname, const char *mode_str) {
    struct stat st;
    if (stat(pathname, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "Error!!! (in file path)");
            exit(1);
        }
    } else if (errno == ENOENT) {
        if (mkdir(pathname, 0700) != 0) {
            perror(pathname);
            exit(1);
        }
    } else {
        perror(pathname);
        exit(1);
    }
    
    mode_t mode = file_permissions(mode_str + 1);
    if (chmod(pathname, mode) != 0) {
        perror(pathname);
        exit(1);
    }
}

// Helper function to apply single file update
static void apply_file_update(FILE *tcbifile, int regular_file) {
    uint8_t block_index_bytes[3];
    if (fread(block_index_bytes, 1, 3, tcbifile) != 3) {
        fprintf(stderr, "Error!!! (in block index)");
        close(regular_file);
        exit(1);
    }
    uint32_t block_index = (uint32_t)block_index_bytes[0] |
                           ((uint32_t)block_index_bytes[1] << 8) |
                           ((uint32_t)block_index_bytes[2] << 16);
    
    uint8_t updates_counter[2];
    if (fread(updates_counter, 1, 2, tcbifile) != 2) {
        fprintf(stderr, "Error!!! (in update lenght)");
        close(regular_file);
        exit(1);
    }
    uint16_t update_len = (uint16_t)updates_counter[0] | 
                         ((uint16_t)updates_counter[1] << 8);
    
    if (update_len > BLOCK_SIZE || update_len == 0) {
        fprintf(stderr, "Error!!! (invalid update length)");
        close(regular_file);
        exit(1);
    }
    
    char *data = malloc(update_len);
    off_t offset = (off_t)block_index * BLOCK_SIZE;
    if (data == NULL ||
        fread(data, 1, update_len, tcbifile) != update_len ||
        lseek(regular_file, offset, SEEK_SET) == (off_t)-1) {
        perror("Error!!! (in update)");
        close(regular_file);
        exit(1);
    }
    ssize_t bytes_written = write(regular_file, data, update_len);
    if (bytes_written != update_len) {
        perror("Error!!! (in byte write)");
        free(data);
        close(regular_file);
        exit(1);
    }
    free(data);
}

// Helper function to handle regular file processing
static void handle_regular_file(FILE *tcbifile, const char *pathname, 
    const char *mode_str, 
                               uint32_t file_size, uint32_t num_updates) {
    int regular_file = open(pathname, O_RDWR | O_CREAT, 0600);
    if (regular_file < 0) {
        perror(pathname);
        exit(1);
    }
    
    for (uint32_t j = 0; j < num_updates; j++) {
        apply_file_update(tcbifile, regular_file);
    }
    
    if (ftruncate(regular_file, (off_t)file_size) != 0) {
        perror("Error!!! (in ftruncate)");
        close(regular_file);
        exit(1);
    }
    close(regular_file);
    
    mode_t mode = file_permissions(mode_str + 1);
    if (chmod(pathname, mode) != 0) {
        perror(pathname);
        exit(1);
    }
}

/// @brief Apply a TCBI file to the filesystem.
/// @param in_pathname A path to where the existing TCBI file is located.
void stage_4(char *in_pathname) {
    FILE *tcbifile = fopen(in_pathname, "rb");
    if (tcbifile == NULL) {
        perror(in_pathname);
        exit(1);
    }
    
    read_tcbi_header(tcbifile);
    
    int num_records = fgetc(tcbifile);
    if (num_records == EOF) {
        fprintf(stderr, "Error!!! (incomplete TCBI)\n");
        exit(1);
    }
    
    for (int i = 0; i < num_records; i++) {
        char *pathname = read_tcbi_pathname(tcbifile);
        
        if (!check_path(pathname)) {
            fprintf(stderr, "Error!!! (in check path)");
            free(pathname);
            exit(1);
        }
        
        char mode_str[11];
        uint32_t file_size, num_updates;
        read_file_metadata(tcbifile, mode_str, &file_size, &num_updates);

        if (mode_str[0] == 'd') {
            handle_directory(pathname, mode_str);
        } else if (mode_str[0] == '-') {
            handle_regular_file(tcbifile, pathname, mode_str, 
                file_size, num_updates);
        } else {
            fprintf(stderr, "Error!!! (in file type)");
            free(pathname);
            exit(1);
        }
        free(pathname);
    }
    
    if (fgetc(tcbifile) != EOF) {
        fprintf(stderr, "Error!!! (extra data in TCBI)");
        fclose(tcbifile);
        exit(1);
    }
    fclose(tcbifile);
}
