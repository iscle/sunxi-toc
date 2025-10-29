#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Types
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t  u8;

// Constants from boot0.h
#define TOC_MAIN_INFO_MAGIC   0x89119800U
#define TOC_MAIN_INFO_END     0x3b45494dU
#define TOC_ITEM_INFO_END     0x3b454949U

// Structs (exact from boot0.h)
typedef struct sbrom_toc1_head_info
{
    char name[16];
    u32  magic;
    u32  add_sum;
    u32  serial_num;
    u32  status;
    u32  items_nr;
    u32  valid_len;
    u32  main_version;
    u32  sub_version;
    u32  reserved[3];
    u32  end;
} sbrom_toc1_head_info_t;

typedef struct sbrom_toc1_item_info
{
    char name[64];
    u32  data_offset;
    u32  data_len;
    u32  encrypt;
    u32  type;
    u32  run_addr;
    u32  index;
    u32  reserved[69];
    u32  end;
} sbrom_toc1_item_info_t;

// Helper: safe string copy
static void safe_strcpy(char *dst, const char *src, size_t len) {
    memcpy(dst, src, len - 1);
    dst[len - 1] = '\0';
}

// Helper: get suffix based on type
const char* get_type_suffix(u32 type) {
    switch (type) {
        case 1: return ".keycert";
        case 2: return ".signcert";
        case 3: return ""; // binary
        default: return ".data";
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <nand_dump.bin>\n", argv[0]);
        return 1;
    }

    FILE *dump = fopen(argv[1], "rb");
    if (!dump) {
        perror("fopen dump");
        return 1;
    }

    // Get file size
    if (fseek(dump, 0, SEEK_END) != 0) {
        perror("fseek end");
        fclose(dump);
        return 1;
    }
    long file_size = ftell(dump);
    if (file_size < (long)sizeof(sbrom_toc1_head_info_t)) {
        fprintf(stderr, "File too small to contain TOC1\n");
        fclose(dump);
        return 1;
    }
    rewind(dump);

    printf("Scanning NAND dump (%ld bytes) for TOC1 headers...\n", file_size);

    // Buffer for header
    sbrom_toc1_head_info_t head;
    long offset = 0;
    int toc_index = 0;

    // Search every 4-byte aligned position (TOC1 is 4-byte aligned)
    while (offset <= file_size - (long)sizeof(sbrom_toc1_head_info_t)) {
        if (fseek(dump, offset, SEEK_SET) != 0) break;
        if (fread(&head, sizeof(head), 1, dump) != 1) break;

        // Check magic and name
        if (head.magic == TOC_MAIN_INFO_MAGIC) {
            char name[17];
            safe_strcpy(name, head.name, sizeof(name));
            if (strcmp(name, "sunxi-secure") == 0) {
                printf("\n[+] Found TOC1 at offset 0x%08lx\n", offset);
                printf("    items_nr = %u, valid_len = %u, version = %u.%u\n",
                       head.items_nr, head.valid_len, head.main_version, head.sub_version);

                if (head.end != TOC_MAIN_INFO_END) {
                    printf("    [!] Warning: Invalid header end marker\n");
                }

                if (head.items_nr == 0 || head.items_nr > 1024) {
                    printf("    [!] Suspicious item count: %u — skipping\n", head.items_nr);
                    offset += 4;
                    continue;
                }

                // Allocate items
                size_t items_size = head.items_nr * sizeof(sbrom_toc1_item_info_t);
                if (offset + sizeof(head) + items_size > (size_t)file_size) {
                    printf("    [!] Not enough data for %u items — skipping\n", head.items_nr);
                    offset += 4;
                    continue;
                }

                sbrom_toc1_item_info_t *items = malloc(items_size);
                if (!items) {
                    perror("malloc items");
                    offset += 4;
                    continue;
                }

                if (fseek(dump, offset + sizeof(head), SEEK_SET) != 0 ||
                    fread(items, items_size, 1, dump) != 1) {
                    printf("    [!] Failed to read items — skipping\n");
                    free(items);
                    offset += 4;
                    continue;
                }

                // Process each item
                for (u32 i = 0; i < head.items_nr; i++) {
                    sbrom_toc1_item_info_t *item = &items[i];

                    if (item->data_len == 0) continue;

                    // Validate data_offset is within file
                    if (item->data_offset >= (u32)file_size ||
                        (u64)item->data_offset + item->data_len > (u64)file_size) {
                        printf("    [!] Item '%.64s': data out of bounds — skipping\n", item->name);
                        continue;
                    }

                    char item_name[65];
                    safe_strcpy(item_name, item->name, sizeof(item_name));
                    const char *suffix = get_type_suffix(item->type);

                    // Unique filename: toc_<index>_<name><suffix>.bin
                    char out_filename[256];
                    snprintf(out_filename, sizeof(out_filename),
                             "toc_%d_%s%s.bin", toc_index, item_name, suffix);

                    FILE *out = fopen(out_filename, "wb");
                    if (!out) {
                        printf("    [!] Cannot create '%s' — skipping\n", out_filename);
                        continue;
                    }

                    // Seek and read data
                    if (fseek(dump, item->data_offset, SEEK_SET) != 0) {
                        fclose(out);
                        continue;
                    }

                    size_t total = 0;
                    size_t remaining = item->data_len;
                    char buffer[65536];

                    while (remaining > 0) {
                        size_t to_read = (remaining > sizeof(buffer)) ? sizeof(buffer) : remaining;
                        size_t n = fread(buffer, 1, to_read, dump);
                        if (n != to_read) break;
                        fwrite(buffer, 1, n, out);
                        total += n;
                        remaining -= n;
                    }

                    fclose(out);
                    printf("    → Extracted %zu bytes to: %s\n", total, out_filename);

                    if (item->encrypt) {
                        printf("      !! Encrypted (AES) — output is ciphertext\n");
                    }
                }

                free(items);
                toc_index++;
                // Skip ahead by valid_len if reasonable, else just +4
                if (head.valid_len > sizeof(head) && head.valid_len < 16 * 1024 * 1024) {
                    offset += head.valid_len;
                } else {
                    offset += 4;
                }
                continue;
            }
        }

        offset += 4; // Search every 4 bytes (TOC1 is 4-byte aligned)
    }

    printf("\nScan complete. Found %d TOC1 instance(s).\n", toc_index);
    fclose(dump);
    return 0;
}