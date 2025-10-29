#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Exact types from boot0.h
typedef uint32_t u32;
typedef uint8_t  u8;

// From boot0.h
#define TOC_MAIN_INFO_MAGIC   0x89119800U
#define TOC_MAIN_INFO_END     0x3b45494dU
#define TOC_ITEM_INFO_END     0x3b454949U

// Exact struct definitions
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

// Helper: safe string copy with null termination
static void safe_strcpy(char *dst, const char *src, size_t len) {
    memcpy(dst, src, len);
    dst[len - 1] = '\0';
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <toc1_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("Error opening TOC1 file");
        return 1;
    }

    // Read main header
    sbrom_toc1_head_info_t head;
    if (fread(&head, sizeof(head), 1, fp) != 1) {
        fprintf(stderr, "Error: Cannot read TOC1 header\n");
        fclose(fp);
        return 1;
    }

    // Validate header
    if (head.magic != TOC_MAIN_INFO_MAGIC) {
        fprintf(stderr, "Error: Invalid TOC1 magic (got 0x%08x, expected 0x%08x)\n",
                head.magic, TOC_MAIN_INFO_MAGIC);
        fclose(fp);
        return 1;
    }
    if (head.end != TOC_MAIN_INFO_END) {
        fprintf(stderr, "Warning: Header end marker invalid (got 0x%08x)\n", head.end);
    }

    // Print header info
    char head_name[17];
    safe_strcpy(head_name, head.name, sizeof(head_name));
    printf("TOC1 Header:\n");
    printf("  name         : %s\n", head_name);
    printf("  magic        : 0x%08x\n", head.magic);
    printf("  items_nr     : %u\n", head.items_nr);
    printf("  valid_len    : %u bytes\n", head.valid_len);
    printf("  version      : %u.%u\n", head.main_version, head.sub_version);

    // Allocate item array
    if (head.items_nr == 0 || head.items_nr > 1024) {
        fprintf(stderr, "Error: Suspicious item count: %u\n", head.items_nr);
        fclose(fp);
        return 1;
    }

    sbrom_toc1_item_info_t *items = calloc(head.items_nr, sizeof(sbrom_toc1_item_info_t));
    if (!items) {
        perror("calloc");
        fclose(fp);
        return 1;
    }

    // Read all item entries
    if (fread(items, sizeof(sbrom_toc1_item_info_t), head.items_nr, fp) != head.items_nr) {
        fprintf(stderr, "Error: Cannot read %u item entries\n", head.items_nr);
        free(items);
        fclose(fp);
        return 1;
    }

    // Process each item
    for (u32 i = 0; i < head.items_nr; i++) {
        sbrom_toc1_item_info_t *item = &items[i];

        // Validate item end marker
        if (item->end != TOC_ITEM_INFO_END) {
            fprintf(stderr, "Warning: Item %u has invalid end marker (0x%08x)\n", i, item->end);
        }

        // Safely get name
        char item_name[65];
        safe_strcpy(item_name, item->name, sizeof(item_name));

        printf("\nItem %u:\n", i);
        printf("  name         : %s\n", item_name);
        printf("  type         : %u ", item->type);
        switch (item->type) {
            case 0: printf("(normal)"); break;
            case 1: printf("(key cert)"); break;
            case 2: printf("(sign cert)"); break;
            case 3: printf("(bin file)"); break;
            default: printf("(unknown)");
        }
        printf("\n");
        printf("  data_offset  : 0x%08x\n", item->data_offset);
        printf("  data_len     : %u bytes\n", item->data_len);
        printf("  encrypt      : %s\n", item->encrypt ? "AES" : "none");
        if (item->type == 3) {
            printf("  run_addr     : 0x%08x\n", item->run_addr);
            printf("  index        : %u\n", item->index);
        }

        if (item->data_len == 0) {
            printf("  -> Skipping (zero-length data)\n");
            continue;
        }

        // Seek to data offset
        if (fseek(fp, item->data_offset, SEEK_SET) != 0) {
            fprintf(stderr, "Error: Cannot seek to offset 0x%x for item '%s'\n",
                    item->data_offset, item_name);
            continue;
        }

        // Open output file
        char out_filename[128];
        snprintf(out_filename, sizeof(out_filename), "%s.bin", item_name);
        FILE *out = fopen(out_filename, "wb");
        if (!out) {
            fprintf(stderr, "Error: Cannot create output file '%s': %s\n",
                    out_filename, strerror(errno));
            continue;
        }

        // Read and write data in chunks
        size_t total = 0;
        size_t remaining = item->data_len;
        char buffer[65536]; // 64KB buffer

        while (remaining > 0) {
            size_t to_read = (remaining > sizeof(buffer)) ? sizeof(buffer) : remaining;
            size_t n = fread(buffer, 1, to_read, fp);
            if (n != to_read) {
                fprintf(stderr, "Error: Short read on item '%s' (expected %zu, got %zu)\n",
                        item_name, to_read, n);
                break;
            }
            if (fwrite(buffer, 1, n, out) != n) {
                fprintf(stderr, "Error: Write failed for '%s'\n", out_filename);
                break;
            }
            total += n;
            remaining -= n;
        }

        fclose(out);
        printf("  -> Extracted %zu bytes to: %s\n", total, out_filename);

        // Note: If encrypt == 1, you'd need to decrypt here (not implemented)
        if (item->encrypt) {
            printf("  !! WARNING: Data is encrypted (AES). Output is ciphertext.\n");
        }
    }

    free(items);
    fclose(fp);
    printf("\nExtraction complete.\n");
    return 0;
}