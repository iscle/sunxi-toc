#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#define PHY_INFO_MAGIC 0xaa55a5a5
#define PHY_INFO_SIZE 0x8000
#define MBR_OFFSET 0x200
#define MAX_PARTITIONS 96
#define EXTRACT_BUFFER_SIZE (1024 * 1024) // 1MB buffer for extraction

// NAND Partition structure (36 bytes)
typedef struct __attribute__((packed)) {
    char classname[16];      // Partition name
    uint32_t addr;           // Start address in sectors
    uint32_t len;            // Length in sectors
    uint32_t user_type;      // User type
    uint32_t keydata;        // Key data flag
    uint32_t ro;             // Read-only flag
} nand_partition_t;

// MBR structure embedded in boot_info
typedef struct __attribute__((packed)) {
    uint32_t crc;            // CRC32
    uint32_t part_count;     // Number of partitions
    nand_partition_t array[MAX_PARTITIONS];
} partition_mbr_t;

// Boot info header (first few fields)
typedef struct __attribute__((packed)) {
    uint32_t magic;          // PHY_INFO_MAGIC = 0xaa55a5a5
    uint32_t len;            // PHY_INFO_SIZE = 0x8000
    uint32_t sum;            // Checksum
} boot_info_header_t;

void sanitize_filename(char *out, const char *in, int max_len) {
    int j = 0;
    for (int i = 0; i < max_len && in[i] != '\0'; i++) {
        if ((in[i] >= 'a' && in[i] <= 'z') ||
            (in[i] >= 'A' && in[i] <= 'Z') ||
            (in[i] >= '0' && in[i] <= '9') ||
            in[i] == '_' || in[i] == '-') {
            out[j++] = in[i];
        }
    }
    out[j] = '\0';
}

int extract_partition(FILE *fp, const nand_partition_t *part, int index,
                      const char *output_dir, long file_size, int is_last) {
    char name[17] = {0};
    char safe_name[17] = {0};
    char filename[256];
    FILE *out_fp;
    uint64_t start_bytes = (uint64_t)part->addr * 512;
    uint64_t size_bytes = (uint64_t)part->len * 512;
    uint8_t *buffer;
    size_t to_read, bytes_read, bytes_written;
    uint64_t total_read = 0;
    int is_eof_partition = 0;

    memcpy(name, part->classname, 16);
    sanitize_filename(safe_name, name, 16);

    // Skip if name is empty
    if (safe_name[0] == '\0') {
        snprintf(safe_name, sizeof(safe_name), "partition_%02d", index);
    }

    // Check if partition is within file bounds
    if (start_bytes >= (uint64_t)file_size) {
        printf("  [SKIP] Partition starts beyond file size\n");
        return 0;
    }

    // If it's the last partition and has zero length, extend to EOF
    if (is_last && part->len == 0) {
        size_bytes = (uint64_t)file_size - start_bytes;
        is_eof_partition = 1;
        printf("  [INFO] Last partition with zero length - extending to EOF\n");
    }

    // Adjust size if it exceeds file bounds
    if (start_bytes + size_bytes > (uint64_t)file_size) {
        uint64_t old_size = size_bytes;
        size_bytes = (uint64_t)file_size - start_bytes;
        printf("  [WARN] Partition size adjusted: %llu -> %llu bytes (file boundary)\n",
               (unsigned long long)old_size, (unsigned long long)size_bytes);
    }

    // Skip zero-length partitions (except for last partition which extends to EOF)
    if (size_bytes == 0) {
        printf("  [SKIP] Zero-length partition\n");
        return 0;
    }

    // Create output filename
    snprintf(filename, sizeof(filename), "%s/%02d_%s.bin",
             output_dir, index, safe_name);

    printf("  [EXTRACT] -> %s ... ", filename);
    fflush(stdout);

    // Open output file
    out_fp = fopen(filename, "wb");
    if (!out_fp) {
        printf("FAILED (can't create file: %s)\n", strerror(errno));
        return 0;
    }

    // Allocate buffer
    buffer = malloc(EXTRACT_BUFFER_SIZE);
    if (!buffer) {
        printf("FAILED (can't allocate buffer)\n");
        fclose(out_fp);
        return 0;
    }

    // Seek to partition start
    if (fseek(fp, start_bytes, SEEK_SET) != 0) {
        printf("FAILED (can't seek to offset)\n");
        free(buffer);
        fclose(out_fp);
        return 0;
    }

    // Extract data
    while (total_read < size_bytes) {
        to_read = (size_bytes - total_read > EXTRACT_BUFFER_SIZE) ?
                  EXTRACT_BUFFER_SIZE : (size_t)(size_bytes - total_read);

        bytes_read = fread(buffer, 1, to_read, fp);
        if (bytes_read == 0) {
            break;
        }

        bytes_written = fwrite(buffer, 1, bytes_read, out_fp);
        if (bytes_written != bytes_read) {
            printf("FAILED (write error)\n");
            free(buffer);
            fclose(out_fp);
            return 0;
        }

        total_read += bytes_read;
    }

    free(buffer);
    fclose(out_fp);

    if (is_eof_partition) {
        printf("OK (%llu bytes to EOF)\n", (unsigned long long)total_read);
    } else {
        printf("OK (%llu bytes)\n", (unsigned long long)total_read);
    }
    return 1;
}

void print_partition(const nand_partition_t *part, int index, long file_size,
                     int is_last, int verbose) {
    char name[17] = {0};
    memcpy(name, part->classname, 16);

    // Calculate sizes
    uint64_t start_bytes = (uint64_t)part->addr * 512;
    uint64_t size_bytes = (uint64_t)part->len * 512;

    // If it's the last partition and has zero length, calculate to EOF
    if (is_last && part->len == 0 && start_bytes < (uint64_t)file_size) {
        size_bytes = (uint64_t)file_size - start_bytes;
    }

    double size_mb = size_bytes / (1024.0 * 1024.0);

    if (verbose) {
        printf("Partition %2d: %-16s", index, name);
        if (is_last && part->len == 0) {
            printf(" [extends to EOF]");
        }
        printf("\n");
        printf("  Start (sectors):  0x%08x (%u)\n", part->addr, part->addr);
        printf("  Start (bytes):    0x%08llx (%llu)\n",
               (unsigned long long)start_bytes, (unsigned long long)start_bytes);
        if (is_last && part->len == 0) {
            printf("  Length (sectors): 0x%08x (%u) [extends to EOF]\n", part->len, part->len);
        } else {
            printf("  Length (sectors): 0x%08x (%u)\n", part->len, part->len);
        }
        printf("  Size (bytes):     0x%08llx (%llu)\n",
               (unsigned long long)size_bytes, (unsigned long long)size_bytes);
        printf("  Size (MB):        %.2f\n", size_mb);
        printf("  User type:        0x%08x\n", part->user_type);
        printf("  Key data:         %u\n", part->keydata);
        printf("  Read-only:        %u\n", part->ro);
    } else {
        // Compact format for non-extracted candidates
        printf("  [%2d] %-16s  Start: 0x%08llx  Size: %7.2f MB",
               index, name, (unsigned long long)start_bytes, size_mb);
        if (is_last && part->len == 0) {
            printf("  [to EOF]");
        }
        printf("\n");
    }
}

int is_printable_name(const char *name, int len) {
    int printable_count = 0;
    for (int i = 0; i < len && name[i] != '\0'; i++) {
        if ((name[i] >= 'a' && name[i] <= 'z') ||
            (name[i] >= 'A' && name[i] <= 'Z') ||
            (name[i] >= '0' && name[i] <= '9') ||
            name[i] == '_' || name[i] == '-') {
            printable_count++;
        }
    }
    return printable_count > 0;
}

int validate_candidate(FILE *fp, long offset, uint32_t *part_count_out) {
    fseek(fp, offset, SEEK_SET);
    boot_info_header_t header;
    if (fread(&header, sizeof(header), 1, fp) != 1) {
        return 0;
    }

    if (header.magic != PHY_INFO_MAGIC || header.len != PHY_INFO_SIZE) {
        return 0;
    }

    long mbr_offset = offset + MBR_OFFSET;
    fseek(fp, mbr_offset, SEEK_SET);

    uint32_t crc, part_count;
    if (fread(&crc, sizeof(uint32_t), 1, fp) != 1 ||
        fread(&part_count, sizeof(uint32_t), 1, fp) != 1) {
        return 0;
    }

    if (part_count == 0 || part_count > MAX_PARTITIONS) {
        return 0;
    }

    nand_partition_t first_part;
    if (fread(&first_part, sizeof(nand_partition_t), 1, fp) != 1) {
        return 0;
    }

    if (!is_printable_name(first_part.classname, 16)) {
        return 0;
    }

    if (first_part.len == 0 && first_part.addr == 0) {
        return 0;
    }

    *part_count_out = part_count;
    return 1;
}

int search_all_candidates(FILE *fp, long **offsets_out, int *count_out) {
    uint32_t magic;
    long pos = 0;
    long file_size;
    int capacity = 10;
    int count = 0;
    long *offsets = malloc(capacity * sizeof(long));

    if (!offsets) {
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    printf("Scanning %ld bytes for PHY_INFO_MAGIC candidates...\n", file_size);

    while (pos < file_size - sizeof(uint32_t)) {
        fseek(fp, pos, SEEK_SET);
        if (fread(&magic, sizeof(uint32_t), 1, fp) != 1) {
            break;
        }

        if (magic == PHY_INFO_MAGIC) {
            uint32_t part_count;
            printf("  Found magic at offset 0x%08lx (%ld) ... ", pos, pos);

            if (validate_candidate(fp, pos, &part_count)) {
                printf("VALID (partitions: %u)\n", part_count);

                if (count >= capacity) {
                    capacity *= 2;
                    offsets = realloc(offsets, capacity * sizeof(long));
                    if (!offsets) {
                        return 0;
                    }
                }
                offsets[count++] = pos;
            } else {
                printf("invalid\n");
            }
        }

        pos += 4;
    }

    *offsets_out = offsets;
    *count_out = count;
    return 1;
}

int parse_and_print_partitions(FILE *fp, long offset, const char *output_dir,
                                int do_extract, int candidate_num, int total_candidates) {
    long file_size;
    int verbose = do_extract; // Verbose mode only for extracted candidate

    // Get file size for boundary checking
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Read boot_info header
    fseek(fp, offset, SEEK_SET);
    boot_info_header_t header;
    if (fread(&header, sizeof(header), 1, fp) != 1) {
        fprintf(stderr, "Error reading boot_info header\n");
        return 0;
    }

    printf("\n============================================\n");
    printf("Candidate %d of %d - PHY_INFO at offset: 0x%08lx (%ld)\n",
           candidate_num + 1, total_candidates, offset, offset);
    if (do_extract) {
        printf("[EXTRACTING TO: %s/]\n", output_dir);
    } else {
        printf("[INFO ONLY - NOT EXTRACTING]\n");
    }
    printf("============================================\n");

    if (verbose) {
        printf("\nBoot Info Header:\n");
        printf("  Magic:    0x%08x\n", header.magic);
        printf("  Length:   0x%08x (%u bytes)\n", header.len, header.len);
        printf("  Checksum: 0x%08x\n", header.sum);
        printf("\n");
    }

    // Seek to MBR structure
    long mbr_offset = offset + MBR_OFFSET;
    fseek(fp, mbr_offset, SEEK_SET);

    // Read MBR header
    uint32_t crc, part_count;
    if (fread(&crc, sizeof(uint32_t), 1, fp) != 1 ||
        fread(&part_count, sizeof(uint32_t), 1, fp) != 1) {
        fprintf(stderr, "Error reading MBR header\n");
        return 0;
    }

    if (verbose) {
        printf("Partition Table (MBR) at offset 0x%08lx:\n", mbr_offset);
        printf("  CRC32:           0x%08x\n", crc);
        printf("  Partition Count: %u\n", part_count);
        printf("\n");
        printf("=== Partition List ===\n\n");
    } else {
        printf("\nPartition Count: %u\n", part_count);
    }

    int extracted_count = 0;

    // Read and display each partition
    for (uint32_t i = 0; i < part_count; i++) {
        nand_partition_t part;
        if (fread(&part, sizeof(nand_partition_t), 1, fp) != 1) {
            fprintf(stderr, "Error reading partition %u\n", i);
            break;
        }

        // Skip empty partitions (unless it's the last partition with len=0)
        int is_last = (i == part_count - 1);
        if (part.addr == 0 && part.len == 0 && part.classname[0] == '\0') {
            continue;
        }

        print_partition(&part, i, file_size, is_last, verbose);

        // Extract partition if requested
        if (do_extract) {
            if (extract_partition(fp, &part, i, output_dir, file_size, is_last)) {
                extracted_count++;
            }
            // Restore position to continue reading partition table
            fseek(fp, mbr_offset + 8 + (i + 1) * sizeof(nand_partition_t), SEEK_SET);
        }

        if (verbose) {
            printf("\n");
        }
    }

    if (verbose) {
        printf("=== Summary ===\n");
        printf("Total partitions: %u\n", part_count);
        if (do_extract) {
            printf("Extracted:        %d\n", extracted_count);
        }
        printf("PHY_INFO offset:  0x%08lx\n", offset);
        printf("MBR offset:       0x%08lx\n", mbr_offset);
    }

    return 1;
}

int main(int argc, char *argv[]) {
    int do_extract = 1; // Always extract by default
    char output_dir[256] = "partitions";
    int extract_candidate = 0; // Which candidate to extract (default: first one)

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <nand_dump_file> [extract_index] [-o output_dir] [--no-extract]\n", argv[0]);
        fprintf(stderr, "\nThis tool parses Allwinner NAND partition tables.\n");
        fprintf(stderr, "It displays ALL valid candidates but only extracts one.\n");
        fprintf(stderr, "\nOptions:\n");
        fprintf(stderr, "  extract_index     Which candidate to extract (0-based, default: 0)\n");
        fprintf(stderr, "  -o output_dir     Output directory for extracted partitions (default: 'partitions')\n");
        fprintf(stderr, "  --no-extract      Don't extract any partitions, only display info\n");
        fprintf(stderr, "\nExamples:\n");
        fprintf(stderr, "  %s dump.bin                    # Show all, extract first to 'partitions/'\n", argv[0]);
        fprintf(stderr, "  %s dump.bin 1                  # Show all, extract second candidate\n", argv[0]);
        fprintf(stderr, "  %s dump.bin -o out             # Show all, extract first to 'out/'\n", argv[0]);
        fprintf(stderr, "  %s dump.bin --no-extract       # Show all, extract none\n", argv[0]);
        return 1;
    }

    // Parse command line arguments
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--no-extract") == 0) {
            do_extract = 0;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            strncpy(output_dir, argv[++i], sizeof(output_dir) - 1);
            output_dir[sizeof(output_dir) - 1] = '\0';
        } else if (argv[i][0] != '-') {
            extract_candidate = atoi(argv[i]);
        }
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("Error opening file");
        return 1;
    }

    // Create output directory if extracting
    if (do_extract) {
        #ifdef _WIN32
        mkdir(output_dir);
        #else
        mkdir(output_dir, 0755);
        #endif
    }

    // Search for all valid candidates
    long *offsets = NULL;
    int count = 0;

    if (!search_all_candidates(fp, &offsets, &count)) {
        fprintf(stderr, "Error during search\n");
        fclose(fp);
        return 1;
    }

    printf("\nFound %d valid PHY_INFO candidate(s)\n", count);

    if (count == 0) {
        fprintf(stderr, "\nNo valid partition tables found!\n");
        free(offsets);
        fclose(fp);
        return 1;
    }

    if (do_extract && (extract_candidate < 0 || extract_candidate >= count)) {
        fprintf(stderr, "Invalid extract index %d (must be 0-%d)\n",
                extract_candidate, count - 1);
        free(offsets);
        fclose(fp);
        return 1;
    }

    // Parse and display ALL candidates
    for (int i = 0; i < count; i++) {
        int should_extract = do_extract && (i == extract_candidate);

        if (!parse_and_print_partitions(fp, offsets[i], output_dir,
                                         should_extract, i, count)) {
            fprintf(stderr, "\nError parsing candidate %d\n", i);
        }

        printf("\n");
    }

    printf("============================================\n");
    printf("Summary: Displayed %d candidate(s)\n", count);
    if (do_extract) {
        printf("Extracted: Candidate %d to %s/\n", extract_candidate, output_dir);
    }
    printf("============================================\n");

    free(offsets);
    fclose(fp);

    return 0;
}