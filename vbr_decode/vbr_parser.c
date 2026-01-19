#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Usage: $ dd count=1 bs=512 skip=128 if=hdd10mb-flat.vmdk 2>/dev/null | ./vbr_parser 

#define VBR_SIZE 512
#define VBR_SIGNATURE 0xAA55

// --- Fixed VBR Structure (Simplified for Robust Parsing) ---
// This structure defines the essential common fields and then uses a single 
// buffer to account for all remaining data, ensuring the signature is aligned at 0x1FE.
typedef struct {
    uint8_t jump_instruction[3];    // Offset 0x00: JMP instruction
    uint8_t oem_id[8];              // Offset 0x03: OEM Name/ID string (e.g., "NTFS    ")
    uint16_t bytes_per_sector;      // Offset 0x0B: Usually 512
    uint8_t sectors_per_cluster;    // Offset 0x0D: Sectors per cluster
    uint16_t reserved_sectors;      // Offset 0x0E: Reserved sectors
    
    // Total bytes defined so far: 3 + 8 + 2 + 1 + 2 = 16 bytes.
    // Remaining bytes before the signature at 0x1FE (510 bytes): 510 - 16 = 494 bytes.
    uint8_t boot_code_and_padding[494]; 

    uint16_t signature;             // Offset 0x1FE: VBR Signature (0x55AA)
} __attribute__((packed)) VBR_Struct;

// --- Known Offsets for File System Detection ---
#define NTFS_TOTAL_SECTORS_OFFSET 0x28
#define FAT32_FS_TYPE_OFFSET      0x52
#define NTFS_MFT_CLUSTER_OFFSET   0x30

/**
 * @brief Reads a 512-byte VBR from standard input and attempts to identify the file system.
 */
int main() {
    VBR_Struct vbr;
    size_t bytes_read;

    // 1. Read the VBR block from standard input
    bytes_read = fread(&vbr, 1, VBR_SIZE, stdin);

    if (bytes_read != VBR_SIZE) {
        fprintf(stderr, "Error: Could not read 512 bytes from stdin. Read %zu bytes.\n", bytes_read);
        fprintf(stderr, "Ensure you are piping the full 512-byte VBR block.\n");
        return EXIT_FAILURE;
    }

    // 2. Verify the VBR signature (must be 0xAA55)
    if (vbr.signature != VBR_SIGNATURE) {
        fprintf(stderr, "Error: Invalid VBR signature. Expected 0x%X, found 0x%X.\n", 
                VBR_SIGNATURE, vbr.signature);
        return EXIT_FAILURE;
    }

    printf("VBR Signature Check: OK (0x%X)\n", VBR_SIGNATURE);
    printf("\n--- Detected File System Details ---\n");
    
    char oem_name[9] = {0};
    memcpy(oem_name, vbr.oem_id, 8);

    // 3. Attempt to detect the File System Type using explicit offsets
    const char *fs_type = "Unknown";
    int detected = 0;

    // Check for NTFS signature (OEM ID usually "NTFS    ")
    if (strncmp(oem_name, "NTFS    ", 8) == 0) {
        fs_type = "NTFS";
        detected = 1;

        // Use pointer arithmetic to safely read the NTFS-specific fields
        uint64_t total_sectors = *(uint64_t*)((uint8_t*)&vbr + NTFS_TOTAL_SECTORS_OFFSET);
        uint64_t mft_cluster = *(uint64_t*)((uint8_t*)&vbr + NTFS_MFT_CLUSTER_OFFSET);

        printf("  File System:              %s\n", fs_type);
        printf("  OEM ID (Signature):       %s\n", oem_name);
        printf("  Total Sectors (NTFS):     %llu\n", (unsigned long long)total_sectors);
        printf("  MFT Start Cluster:        %llu\n", (unsigned long long)mft_cluster);
    } 
    // Check for FAT32 signature (String at offset 0x52 usually "FAT32   ")
    else if (strncmp((char*)((uint8_t*)&vbr + FAT32_FS_TYPE_OFFSET), "FAT32   ", 8) == 0) {
        fs_type = "FAT32";
        detected = 1;
        printf("  File System:              %s\n", fs_type);
        printf("  OEM ID:                   %s\n", oem_name);
        printf("  FAT Type Signature:       %s\n", (char*)((uint8_t*)&vbr + FAT32_FS_TYPE_OFFSET));
    } 
    // Check for common FAT/other MS-DOS variants
    else if (strncmp(oem_name, "MSDOS", 5) == 0 || strncmp(oem_name, "MSWIN", 5) == 0) {
        fs_type = "FAT (Possible FAT16 or FAT32)";
        detected = 1;
        printf("  File System:              %s\n", fs_type);
        printf("  OEM ID (Signature):       %s\n", oem_name);
    }

    if (!detected) {
        printf("  File System:              %s\n", fs_type);
        printf("  Unrecognized OEM ID:      %s\n", oem_name);
    }

    printf("  Bytes/Sector:             %u\n", vbr.bytes_per_sector);
    printf("  Sectors/Cluster:          %u\n", vbr.sectors_per_cluster);

    printf("-----------------------------------------\n");

    return EXIT_SUCCESS;
}
