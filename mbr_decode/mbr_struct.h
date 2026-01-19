#include <stdint.h>

#define MBR_PARTITION_COUNT 4
#define MBR_SIGNATURE_VALUE 0xAA55

// --- 1. Partition Table Entry Structure (16 bytes) ---
// Each of the four primary partitions is described by one of these entries.
typedef struct {
    uint8_t boot_indicator;     // 0x80 = Active/Bootable, 0x00 = Inactive
    uint8_t starting_head;
    uint8_t starting_sector : 6;
    uint8_t starting_cylinder_high : 2;
    uint8_t starting_cylinder;
    uint8_t system_id;          // Partition type (e.g., 0x07 for NTFS, 0x0B for FAT32)
    uint8_t ending_head;
    uint8_t ending_sector : 6;
    uint8_t ending_cylinder_high : 2;
    uint8_t ending_cylinder;
    uint32_t lba_starting_sector; // LBA of the first sector in the partition (Little-endian)
    uint32_t sector_count;      // Total number of sectors in the partition (Little-endian)
} __attribute__((packed)) MBR_PartitionEntry;

// --- 2. Master Boot Record Structure (512 bytes) ---
typedef struct {
    uint8_t boot_code[440];     // The bootstrap code/loader (440 bytes)
    uint8_t disk_signature[4];  // Optional Disk Signature/Unique ID (4 bytes)
    uint16_t reserved;          // Usually 0x0000 (2 bytes)

    MBR_PartitionEntry partitions[MBR_PARTITION_COUNT]; // The Partition Table (4 * 16 = 64 bytes)

    uint16_t signature;         // MBR Signature (0x55AA - Note: Little-endian storage means 0xAA55)
} __attribute__((packed)) MBR_Struct;

