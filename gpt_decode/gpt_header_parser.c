#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// GPT Signature: "EFI PART" (0x45 46 49 20 50 41 52 54)
#define GPT_SIGNATURE 0x5452415020494645ULL 
#define GPT_HEADER_SIZE 92 // The specified size of the header structure

// --- Utility function to format and print a GUID ---
void print_guid(const uint8_t *guid, const char *name) {
    // GUIDs are typically stored as 16 bytes. They are printed in 
    // DWORDS (4-2-2-2-6 byte blocks) with specific endianness swaps.
    // For simplicity, we print it as a standard hex array.
    printf("  %-26s: %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
           name,
           guid[3], guid[2], guid[1], guid[0], // DWord 1 (Little-Endian)
           guid[5], guid[4],                  // Word 2
           guid[7], guid[6],                  // Word 3
           guid[8], guid[9],                  // Bytes 8, 9
           guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]);
}

// --- 1. GPT Header Structure (512 bytes total) ---
typedef struct {
    uint64_t signature;           // Offset 0x00: "EFI PART" (0x5452415020494645)
    uint32_t revision;            // Offset 0x08: GPT revision (e.g., 0x00010000)
    uint32_t header_size;         // Offset 0x0C: Size of the GPT header (92 bytes)
    uint32_t header_crc32;        // Offset 0x10: CRC32 of the header (with this field zeroed)
    uint32_t reserved1;           // Offset 0x14: Must be 0
    uint64_t current_lba;         // Offset 0x18: LBA of this header (usually 1)
    uint64_t backup_lba;          // Offset 0x20: LBA of the backup header
    uint64_t first_usable_lba;    // Offset 0x28: First LBA available for partitions
    uint64_t last_usable_lba;     // Offset 0x30: Last LBA available for partitions
    uint8_t disk_guid[16];        // Offset 0x38: Unique Disk GUID (16 bytes)
    uint64_t partition_entry_lba; // Offset 0x48: LBA of the partition entry array (usually 2)
    uint32_t num_partition_entries; // Offset 0x50: Number of entries in the array (e.g., 128)
    uint32_t partition_entry_size; // Offset 0x54: Size of each entry (usually 128 bytes)
    uint32_t partition_array_crc32; // Offset 0x58: CRC32 of the entire partition entry array
    uint8_t reserved2[420];       // Offset 0x5C: Reserved (to pad to 512 bytes)
} __attribute__((packed)) GPT_Header;





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
 * @brief Reads a 512-byte GPT Header from standard input and prints key details.
 */
int main() {
    GPT_Header header;
    size_t bytes_read;

    // 1. Read the GPT Header (LBA 1) from standard input
    bytes_read = fread(&header, 1, sizeof(GPT_Header), stdin);

    if (bytes_read != sizeof(GPT_Header)) {
        fprintf(stderr, "Error: Could not read 512 bytes from stdin. Read %zu bytes.\n", bytes_read);
        fprintf(stderr, "Ensure you are piping the full 512-byte GPT Header block (LBA 1).\n");
        return EXIT_FAILURE;
    }

    // 2. Verify the GPT signature
    if (header.signature != GPT_SIGNATURE) {
        fprintf(stderr, "Error: Invalid GPT Signature. Expected 'EFI PART', found 0x%llX.\n", 
                (unsigned long long)header.signature);
        return EXIT_FAILURE;
    }

    printf("GPT Signature Check: OK ('EFI PART')\n");

    printf("--- GPT Header Raw Bytes ---\n");
    print_raw_bytes((uint8_t *)&header, GPT_HEADER_SIZE);

    printf("\n--- GPT Header Details ---\n");
    
    // 3. Print key header details
    printf("  Revision:                 v%u.%u\n", 
           (header.revision >> 16) & 0xFFFF, header.revision & 0xFFFF);
    printf("  Header Size:              %u bytes (Expected %u)\n", 
           header.header_size, GPT_HEADER_SIZE);
    
    print_guid(header.disk_guid, "Disk GUID");

    printf("\n  Current LBA:              %llu\n", (unsigned long long)header.current_lba);
    printf("  Backup LBA:               %llu\n", (unsigned long long)header.backup_lba);

    printf("\n--- Partition Entry Location ---\n");
    printf("  Partition Entry Start LBA: %llu\n", (unsigned long long)header.partition_entry_lba);
    printf("  Max Partition Entries:    %u\n", header.num_partition_entries);
    printf("  Entry Size:               %u bytes\n", header.partition_entry_size);
    
    printf("\n--- Usable Disk Space ---\n");
    printf("  First Usable LBA:         %llu\n", (unsigned long long)header.first_usable_lba);
    printf("  Last Usable LBA:          %llu\n", (unsigned long long)header.last_usable_lba);
    
    // Total usable sectors = LastUsable - FirstUsable + 1
    uint64_t total_sectors = header.last_usable_lba - header.first_usable_lba + 1;
    // Estimated size assuming 512-byte sectors
    double total_size_gb = (double)total_sectors * 512.0 / (1024.0 * 1024.0 * 1024.0);
    
    printf("  Total Usable Sectors:     %llu\n", (unsigned long long)total_sectors);
    printf("  Total Usable Size:        %.2f GB\n", total_size_gb);
    printf("--------------------------------\n");

    return EXIT_SUCCESS;
}
