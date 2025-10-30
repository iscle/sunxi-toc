#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define PHY_INFO_MAGIC 0xaa55a5a5
#define PHY_INFO_SIZE 0x8000
#define MBR_OFFSET 0x200
#define MAX_PARTITIONS 96

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

void print_partition(const nand_partition_t *part, int index) {
    char name[17] = {0};
    memcpy(name, part->classname, 16);

    // Calculate sizes
    uint64_t start_bytes = (uint64_t)part->addr * 512;
    uint64_t size_bytes = (uint64_t)part->len * 512;
    double size_mb = size_bytes / (1024.0 * 1024.0);

    printf("Partition %2d: %-16s\n", index, name);
    printf("  Start (sectors):  0x%08x (%u)\n", part->addr, part->addr);
    printf("  Start (bytes):    0x%08llx (%llu)\n",
           (unsigned long long)start_bytes, (unsigned long long)start_bytes);
    printf("  Length (sectors): 0x%08x (%u)\n", part->len, part->len);
    printf("  Size (bytes):     0x%08llx (%llu)\n",
           (unsigned long long)size_bytes, (unsigned long long)size_bytes);
    printf("  Size (MB):        %.2f\n", size_mb);
    printf("  User type:        0x%08x\n", part->user_type);
    printf("  Key data:         %u\n", part->keydata);
    printf("  Read-only:        %u\n", part->ro);
    printf("\n");
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
    return printable_count > 0; // At least one valid char
}

int validate_candidate(FILE *fp, long offset, uint32_t *part_count_out) {
    // Read boot_info header
    fseek(fp, offset, SEEK_SET);
    boot_info_header_t header;
    if (fread(&header, sizeof(header), 1, fp) != 1) {
        return 0;
    }

    // Validate magic (should be already checked, but double-check)
    if (header.magic != PHY_INFO_MAGIC) {
        return 0;
    }

    // Validate length field
    if (header.len != PHY_INFO_SIZE) {
        return 0;
    }

    // Seek to MBR
    long mbr_offset = offset + MBR_OFFSET;
    fseek(fp, mbr_offset, SEEK_SET);

    uint32_t crc, part_count;
    if (fread(&crc, sizeof(uint32_t), 1, fp) != 1 ||
        fread(&part_count, sizeof(uint32_t), 1, fp) != 1) {
        return 0;
    }

    // Validate partition count
    if (part_count == 0 || part_count > MAX_PARTITIONS) {
        return 0;
    }

    // Read first partition to validate
    nand_partition_t first_part;
    if (fread(&first_part, sizeof(nand_partition_t), 1, fp) != 1) {
        return 0;
    }

    // Check if first partition has reasonable values
    if (!is_printable_name(first_part.classname, 16)) {
        return 0;
    }

    // Partition should have non-zero length (usually)
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

    // Get file size
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    printf("Scanning %ld bytes for PHY_INFO_MAGIC candidates...\n", file_size);

    // Search for all occurrences of PHY_INFO_MAGIC
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

                // Add to array
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

        pos += 4; // Move by 4 bytes for alignment
    }

    *offsets_out = offsets;
    *count_out = count;
    return 1;
}

int parse_and_print_partitions(FILE *fp, long offset) {
    // Read boot_info header
    fseek(fp, offset, SEEK_SET);
    boot_info_header_t header;
    if (fread(&header, sizeof(header), 1, fp) != 1) {
        fprintf(stderr, "Error reading boot_info header\n");
        return 0;
    }

    printf("\nBoot Info Header:\n");
    printf("  Magic:    0x%08x\n", header.magic);
    printf("  Length:   0x%08x (%u bytes)\n", header.len, header.len);
    printf("  Checksum: 0x%08x\n", header.sum);
    printf("\n");

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

    printf("Partition Table (MBR) at offset 0x%08lx:\n", mbr_offset);
    printf("  CRC32:           0x%08x\n", crc);
    printf("  Partition Count: %u\n", part_count);
    printf("\n");

    printf("=== Partition List ===\n\n");

    // Read and display each partition
    for (uint32_t i = 0; i < part_count; i++) {
        nand_partition_t part;
        if (fread(&part, sizeof(nand_partition_t), 1, fp) != 1) {
            fprintf(stderr, "Error reading partition %u\n", i);
            break;
        }

        // Skip empty partitions
        if (part.addr == 0 && part.len == 0 && part.classname[0] == '\0') {
            continue;
        }

        print_partition(&part, i);
    }

    printf("=== Summary ===\n");
    printf("Total partitions: %u\n", part_count);
    printf("PHY_INFO offset:  0x%08lx\n", offset);
    printf("MBR offset:       0x%08lx\n", mbr_offset);

    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <nand_dump_file> [candidate_index]\n", argv[0]);
        fprintf(stderr, "\nThis tool parses Allwinner NAND partition tables.\n");
        fprintf(stderr, "It searches for all PHY_INFO structures and validates them.\n");
        fprintf(stderr, "\nIf multiple valid candidates are found:\n");
        fprintf(stderr, "  - Without [candidate_index]: shows the first valid one\n");
        fprintf(stderr, "  - With [candidate_index]: shows the specified candidate (0-based)\n");
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("Error opening file");
        return 1;
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
        fprintf(stderr, "This could mean:\n");
        fprintf(stderr, "  - The dump is corrupted\n");
        fprintf(stderr, "  - The partition table uses a different format\n");
        fprintf(stderr, "  - The magic bytes are present but data is invalid\n");
        free(offsets);
        fclose(fp);
        return 1;
    }

    // Determine which candidate to display
    int candidate_index = 0;
    if (argc >= 3) {
        candidate_index = atoi(argv[2]);
        if (candidate_index < 0 || candidate_index >= count) {
            fprintf(stderr, "Invalid candidate index %d (must be 0-%d)\n",
                    candidate_index, count - 1);
            free(offsets);
            fclose(fp);
            return 1;
        }
    }

    if (count > 1) {
        printf("\n=== Using candidate %d of %d ===\n", candidate_index, count);
        printf("(Run with argument '%d' through '%d' to view other candidates)\n\n",
               0, count - 1);
    }

    printf("\n============================================\n");
    printf("Parsing PHY_INFO at offset: 0x%08lx (%ld)\n",
           offsets[candidate_index], offsets[candidate_index]);
    printf("============================================\n");

    if (!parse_and_print_partitions(fp, offsets[candidate_index])) {
        free(offsets);
        fclose(fp);
        return 1;
    }

    free(offsets);
    fclose(fp);

    return 0;
}