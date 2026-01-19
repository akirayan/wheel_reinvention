#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MBR_PARTITION_COUNT 4
#define MBR_SIGNATURE_VALUE 0xAA55

// --- 1. Partition Table Entry Structure (16 bytes) ---
// We use __attribute__((packed)) to ensure the compiler doesn't add padding.
typedef struct {
    uint8_t boot_indicator;     // 0x80 = Active, 0x00 = Inactive
    uint8_t starting_head;
    // Bit fields for C/H/S addressing. Note: These are often unused/ignored in modern systems.
    uint8_t starting_sector_low : 6;
    uint8_t starting_cylinder_high : 2;
    uint8_t starting_cylinder;
    uint8_t system_id;          // Partition type (e.g., 0x07 for NTFS, 0x83 for Linux)
    uint8_t ending_head;
    uint8_t ending_sector_low : 6;
    uint8_t ending_cylinder_high : 2;
    uint8_t ending_cylinder;
    uint32_t lba_starting_sector; // LBA of the first sector (4 bytes, Little-endian)
    uint32_t sector_count;      // Total number of sectors in the partition (4 bytes, Little-endian)
} __attribute__((packed)) MBR_PartitionEntry;

// --- 2. Master Boot Record Structure (512 bytes) ---
typedef struct {
    uint8_t boot_code[440];     // Bootstrap Code Area
    uint8_t disk_signature[4];  // Optional Disk Signature/Unique ID
    uint16_t reserved;          // Usually 0x0000

    MBR_PartitionEntry partitions[MBR_PARTITION_COUNT]; // The Partition Table (64 bytes)

    uint16_t signature;         // MBR Signature (0x55AA)
} __attribute__((packed)) MBR_Struct;

// --- 3. Partition Type Lookup Table ---
typedef struct {
    uint8_t id;
    const char *description;
} PartitionType;

const PartitionType type_table[] = {
    {0x00, "Empty/Unused"},
    {0x01, "FAT12"},
    {0x04, "FAT16 (<32MB)"},
    {0x05, "Extended (CHS)"},
    {0x06, "FAT16"},
    {0x07, "NTFS / exFAT / HPFS"},
    {0x0B, "FAT32"},
    {0x0C, "FAT32 (LBA)"},
    {0x0F, "Extended (LBA)"},
    {0x17, "Hidden NTFS / exFAT"},
    {0x82, "Linux Swap / Solaris"},
    {0x83, "Linux Filesystem"},
    {0x84, "OS/2 Boot Manager"},
    {0x8E, "Linux LVM"},
    {0xEE, "GPT Protective MBR"},
    {0xEF, "EFI System Partition (FAT)"},
    {0xFD, "Linux RAID auto-detect"},
    {0xFE, "LANstep / PS/2 ESDI"},
    {0xFF, "XENIX Bad Block Table"}
};

/**
 * @brief Translates a hex System ID into a human-readable description string.
 * @param id The partition System ID byte (e.g., 0x07, 0x83, 0xEE).
 * @return A static string describing the partition type, or "Unknown Type" if not found.
 */
const char* get_partition_type_description(uint8_t id) {
    size_t table_size = sizeof(type_table) / sizeof(type_table[0]);
    for (size_t i = 0; i < table_size; ++i) {
        if (type_table[i].id == id) {
            return type_table[i].description;
        }
    }
    return "Unknown Type";
}

/**
 * @brief Print each byte as hex
 * @param p The starting address
 * @param length The count of bytes to print
 */
void print_raw_bytes(uint8_t *p, int length) {
    for (int i=0; i < length; ++i) {
        printf("%02x ", *(p + i));
        if (((i+1) % 8)==0) printf(" ");
        if (((i+1) % 16)==0) printf("\n");
    }
    printf("\n");
}


/**
 * @brief Reads a 512-byte MBR from standard input and prints partition details in a table.
 */
int main() {
    MBR_Struct mbr;
    size_t bytes_read;

    // 1. Read the MBR from standard input
    bytes_read = fread(&mbr, 1, sizeof(MBR_Struct), stdin);

    if (bytes_read != sizeof(MBR_Struct)) {
        fprintf(stderr, "Error: Could not read 512 bytes from stdin. Read %zu bytes.\n", bytes_read);
        fprintf(stderr, "Ensure you are piping the full 512-byte MBR block.\n");
        return EXIT_FAILURE;
    }

    // 2. Verify the MBR signature
    if (mbr.signature != MBR_SIGNATURE_VALUE) {
        fprintf(stderr, "Error: Invalid MBR signature. Expected 0x%X, found 0x%X.\n", 
                MBR_SIGNATURE_VALUE, mbr.signature);
    } else {
        printf("MBR Signature Check: OK (0x%X)\n", MBR_SIGNATURE_VALUE);
    }

    // print other bytes
    printf("Disk Signature: ");
    print_raw_bytes((uint8_t *)mbr.disk_signature, 4);

    // print the partition table as raw format
    for (int i = 0; i < MBR_PARTITION_COUNT; ++i) {
        MBR_PartitionEntry *p = &mbr.partitions[i];
        printf("P%1d: ", i + 1);
        print_raw_bytes((uint8_t *)p, sizeof(MBR_PartitionEntry));
    }

    // 3. Print the Partition Table
    printf("\n--- Partition Table (fdisk-style) ---\n");
    
    // Table Header (using fixed widths for alignment)
    printf("Device | Boot | Start LBA |  Sectors   | Size (GB) | Id | Type\n");
    printf("-------+------+-----------+------------+-----------+----+--------------------------\n");

    for (int i = 0; i < MBR_PARTITION_COUNT; ++i) {
        MBR_PartitionEntry *p = &mbr.partitions[i];

        if (p->system_id == 0x00) {
            // Print empty row
            printf(" P%-4d |      |           |            |           | 00 | Empty/Unused\n", i + 1);
        } else {
            const char* type_desc = get_partition_type_description(p->system_id);
            // Use '*' for bootable flag, or ' ' for non-bootable
            const char* boot_char = (p->boot_indicator == 0x80 ? "*" : " ");
            
            // Calculate size in GB
            float size_gb = (float)p->sector_count * 512.0 / (1024.0 * 1024.0 * 1024.0);

            // Print the row with fixed-width formatting
            // Format:  " %-4s | %-4s | %10u | %10u | %9.2fG | %02X | %-24s\n"
            printf(" P%-4d | %-4s | %10u | %10u | %7.2f G | %02X | %-24s\n", 
                   i + 1,
                   boot_char,
                   p->lba_starting_sector,
                   p->sector_count,
                   size_gb,
                   p->system_id,
                   type_desc);
        }
    }
    printf("--------------------------------------------------------------------------------\n");

    return EXIT_SUCCESS;
}
