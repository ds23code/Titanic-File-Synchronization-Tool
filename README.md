# Titanic - File Synchronization Tool

A block-based file synchronization utility written in C that efficiently tracks and applies file changes using cryptographic hashing. Similar to tools like rsync, it minimizes data transfer by identifying which blocks of files have changed.

## Project Overview

Titanic is a multi-stage file synchronization system that creates indexed representations of files, compares them to detect changes, and applies updates efficiently. The tool uses 64-bit FNV-1a hashing to identify unchanged blocks, reducing the amount of data that needs to be transferred or updated.

**Author:** Dhruv Sharma
**Language:** C  
## Features

- **Block-Based Hashing**: Files are divided into 256-byte blocks, each identified by a unique hash
- **Efficient Change Detection**: Only modified blocks are identified and transferred
- **Four-Stage Pipeline**: Progressive transformation from file list to applied updates
- **Binary File Formats**: Custom compact binary formats for efficient storage
- **Path Safety**: Validates paths to prevent directory traversal attacks
- **Permission Preservation**: Maintains Unix file permissions through synchronization

## Architecture

### Stage 1: TABI Creation (`--stage-1`)
**Type A Block Index** - Creates an index of all files and their block hashes.

```bash
./titanic --stage-1 output.tabi file1.txt file2.txt file3.txt
```

**Output Format:**
```
[TABI Magic: 4 bytes]
[Number of files: 1 byte]
For each file:
  [Path length: 2 bytes]
  [Path: variable]
  [Number of blocks: 3 bytes]
  [Block hashes: 8 bytes each]
```

### Stage 2: TBBI Creation (`--stage-2`)
**Type B Block Index** - Compares TABI against local files to identify matching blocks.

```bash
./titanic --stage-2 output.tbbi input.tabi
```

**Output Format:**
```
[TBBI Magic: 4 bytes]
[Number of files: 1 byte]
For each file:
  [Path length: 2 bytes]
  [Path: variable]
  [Number of blocks: 3 bytes]
  [Match bitmap: variable]
    Each bit represents whether corresponding block matches (1) or not (0)
```

### Stage 3: TCBI Creation (`--stage-3`)
**Type C Block Index** - Creates a changeset with only blocks that need updating.

```bash
./titanic --stage-3 output.tcbi input.tbbi
```

**Output Format:**
```
[TCBI Magic: 4 bytes]
[Number of files: 1 byte]
For each file:
  [Path length: 2 bytes]
  [Path: variable]
  [File type + permissions: 10 bytes] (e.g., "-rwxr-xr-x")
  [File size: 4 bytes]
  [Number of updates: 3 bytes]
  For each update:
    [Block index: 3 bytes]
    [Update length: 2 bytes]
    [Block data: variable, max 256 bytes]
```

### Stage 4: Apply TCBI (`--stage-4`)
Applies the changeset to the filesystem.

```bash
./titanic --stage-4 input.tcbi
```

**Actions:**
- Creates/updates files and directories
- Writes only changed blocks to files
- Sets correct file permissions
- Validates paths for security

## Technical Implementation

### Block Hashing

Uses **64-bit FNV-1a** hash algorithm:

```c
uint64_t hash_block(char block[], size_t block_size) {
    uint64_t hash = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < block_size; ++i) {
        hash ^= (unsigned char) block[i];
        hash *= 0x100000001b3;
    }
    return hash;
}
```

### Key Functions

**Stage 1 Helpers:**
- `write_tabi_header()` - Writes TABI magic and file count
- `process_single_file()` - Hashes all blocks of a file
- `process_file_blocks()` - Reads and hashes individual blocks

**Stage 2 Helpers:**
- `compare_local_blocks()` - Compares local file blocks against hashes
- `read_hashes_from_file()` - Reads hash array from TABI
- `check_record()` - Processes one file record

**Stage 3 Helpers:**
- `count_updates_needed()` - Counts non-matching blocks from bitmap
- `write_update_data()` - Extracts and writes changed block data
- `write_file_permissions()` - Converts mode_t to string format

**Stage 4 Helpers:**
- `check_path()` - Validates path safety (no `..` escaping, no absolute paths)
- `file_permissions()` - Converts permission string to mode_t
- `apply_file_update()` - Writes single block update to file
- `handle_regular_file()` - Processes file updates and sets permissions

### Data Structures

```c
// File block comparison state
struct {
    uint16_t path_length;
    char pathname[PATH_MAX];
    uint32_t num_blocks;
    uint64_t *hashes;         // Array of block hashes
    uint8_t *match_bitmap;    // Bitmap of matching blocks
}

// Update record
struct {
    uint32_t block_index;     // Which block to update
    uint16_t update_length;   // How many bytes (≤256)
    char data[BLOCK_SIZE];    // Block content
}
```

## Security Features

1. **Path Validation**: Rejects absolute paths and paths that escape current directory
2. **Bounded Reads**: All file operations validate lengths against maximums
3. **Permission Control**: Files created with restricted permissions (0600), then set to specified mode
4. **Error Handling**: Comprehensive error checking on all I/O operations

## Usage Examples

### Basic Synchronization Workflow

```bash
# 1. Create index of source files
./titanic --stage-1 source.tabi file1.txt file2.txt dir/file3.txt

# 2. Compare against local copies
./titanic --stage-2 changes.tbbi source.tabi

# 3. Create changeset
./titanic --stage-3 updates.tcbi changes.tbbi

# 4. Apply changes
./titanic --stage-4 updates.tcbi
```

### Hashing a Single Block

```bash
# Hash up to 256 bytes from stdin
./titanic-hash-block < file.txt
# Output: 64-bit hex hash
```

## File Format Details

### Little-Endian Encoding
All multi-byte integers stored in little-endian format:
```c
// Writing 3-byte integer
fputc(value & 0xFF, file);
fputc((value >> 8) & 0xFF, file);
fputc((value >> 16) & 0xFF, file);
```

### Match Bitmap Encoding
Blocks are packed 8 per byte, MSB first:
```
Block indices:  0  1  2  3  4  5  6  7 | 8  9 10 11 12 13 14 15
Bit positions: 7  6  5  4  3  2  1  0 | 7  6  5  4  3  2  1  0
Byte index:          Byte 0            |        Byte 1
```

## Constants

```c
#define BLOCK_SIZE 256           // Size of each file block
#define PATH_MAX 4096            // Maximum path length
#define MATCH_BYTE_BITS 8        // Bits per match byte
#define MAGIC_SIZE 4             // Size of magic numbers
#define NUM_RECORDS_SIZE 1       // Size of record count
#define HASH_SIZE 8              // Size of block hash
```

## Building

```bash
# Compile all stages
gcc -Wall -Wextra -std=c11 -o titanic \
    titanic_main.c titanic.c titanic_provided.c

# Compile hash utility
gcc -Wall -Wextra -std=c11 -o titanic-hash-block \
    titanic_hash_block.c titanic_provided.c
```

## Error Handling

The program exits with error messages for:
- File I/O failures
- Invalid file format (wrong magic numbers)
- Memory allocation failures
- Invalid paths (directory traversal attempts)
- File stat errors
- Permission setting failures

## Performance Characteristics

- **Time Complexity**: O(n × b) where n = number of files, b = blocks per file
- **Space Complexity**: O(b) for hash storage per file
- **Block Size**: 256 bytes balances granularity vs. overhead
- **Hash Collisions**: FNV-1a provides good distribution for 64-bit space

## Limitations

- No compression of block data
- No network transfer capability (file-based only)
- Single-threaded processing
- No support for symbolic links
- Maximum 255 files per index
- Block size fixed at 256 bytes

## Use Cases

- **Backup Systems**: Identify changed blocks for incremental backups
- **Version Control**: Track file changes at block level
- **Remote Sync**: Generate minimal update payloads (requires external transfer)
- **Data Deduplication**: Identify duplicate blocks across files

## Learning Outcomes

This project demonstrates:
- **Binary File I/O**: Reading and writing custom binary formats
- **Bitwise Operations**: Bitmap manipulation for block matching
- **File System Operations**: Creating files/directories, setting permissions
- **Memory Management**: Dynamic allocation for variable-sized data
- **Cryptographic Hashing**: Using hash functions for data integrity
- **System Calls**: Unix file operations (open, write, ftruncate, chmod, mkdir)
- **Error Handling**: Robust error checking for production code

## Testing

Example test workflow:
```bash
# Create test files
echo "Hello World" > test1.txt
echo "Goodbye World" > test2.txt

# Run through pipeline
./titanic --stage-1 test.tabi test1.txt test2.txt
./titanic --stage-2 test.tbbi test.tabi
./titanic --stage-3 test.tcbi test.tbbi

# Modify a file
echo "Hello Universe" > test1.txt

# Re-run stages 2-3 to detect change
./titanic --stage-2 test.tbbi test.tabi
./titanic --stage-3 test.tcbi test.tbbi
./titanic --stage-4 test.tcbi
```
