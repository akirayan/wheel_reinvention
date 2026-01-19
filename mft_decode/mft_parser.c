#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MFT_RECORD_SIZE 1024 // Default size of an MFT record
#define MFT_SIGNATURE 0x454C4946 // 'FILE' in Little-Endian
#define EPOCH_DIFFERENCE 116444736000000000ULL // 100ns intervals between 1601 and 1970

// --- 1. MFT Record Header Structure (48 bytes) ---
typedef struct {
    uint32_t signature;          // Offset 0x00: Must be 'FILE'
    uint16_t fixup_offset;       // Offset 0x04
    uint16_t fixup_size;         // Offset 0x06
    uint64_t lsn;                // Offset 0x08
    uint16_t sequence_number;    // Offset 0x10
    uint16_t link_count;         // Offset 0x12
    uint16_t first_attribute;    // Offset 0x14: Offset to the first Attribute record
    uint16_t flags;              // Offset 0x16: 0x0001=In Use, 0x0002=Directory
    uint32_t real_size;          // Offset 0x18: Size of the record data
    uint32_t allocated_size;     // Offset 0x1C: Total allocated size (usually 1024)
    uint64_t base_mft_record;    // Offset 0x20
    uint16_t next_record_id;     // Offset 0x28
    uint16_t reserved;           // Offset 0x2A
    uint32_t mft_record_number;  // Offset 0x2C
} __attribute__((packed)) MFT_Record_Header;

// --- 2. Generic Attribute Header Structure ---
typedef struct {
    uint32_t type_code;          // Offset 0x00: Attribute type
    uint32_t length;             // Offset 0x04: Length of the attribute record
    uint8_t non_resident;        // Offset 0x08: 0=Resident, 1=Non-Resident
    uint8_t name_length;         // Offset 0x09
    uint16_t name_offset;        // Offset 0x0A
    uint16_t flags;              // Offset 0x0C
    uint16_t attribute_id;       // Offset 0x0E
    
    union {
        // Resident (Data inside the MFT record)
        struct {
            uint32_t value_length;  // Offset 0x10
            uint16_t value_offset;  // Offset 0x14
            uint8_t indexed_flag;   // Offset 0x16
            uint8_t reserved;       // Offset 0x17
        } resident;
        
        // Non-Resident (Data stored elsewhere - COMPLETE fields)
        struct {
            uint64_t starting_vcn;       // Offset 0x10: First Virtual Cluster Number
            uint64_t ending_vcn;         // Offset 0x18: Last VCN
            uint16_t data_runs_offset;   // Offset 0x20: Offset to Data Runs list
            uint16_t compression_unit;   // Offset 0x22: Compression unit size (log base 2)
            uint32_t reserved_padding;   // Offset 0x24: Reserved (must be zero)
            uint64_t allocated_size;     // Offset 0x28: Space allocated on disk (bytes)
            uint64_t real_size;          // Offset 0x30: Actual data size (bytes)
            uint64_t initialized_size;   // Offset 0x38: Initialized data size (bytes)
            uint64_t compressed_size;    // Offset 0x40: Compressed data size (bytes, if compressed)
            uint64_t reserved_final;     // Offset 0x48: Reserved
        } __attribute__((packed)) non_resident;
    } details;

} __attribute__((packed)) MFT_Attribute_Header;

// --- 3. Attribute Value Structures (Resident) ---

// $STANDARD_INFORMATION (Type 0x10) Value - 72 bytes
typedef struct {
    uint64_t creation_time;      // Offset 0x00
    uint64_t last_mft_change;    // Offset 0x08
    uint64_t last_access_time;   // Offset 0x10
    uint64_t last_mod_time;      // Offset 0x18
    uint32_t dos_permissions;    // Offset 0x20 (DOS file attributes)
    uint32_t max_versions;       // Offset 0x24
    uint32_t version_num;        // Offset 0x28
    uint32_t class_id;           // Offset 0x2C
    uint32_t owner_id;           // Offset 0x30
    uint32_t security_id;        // Offset 0x34
    uint64_t quota_charged;      // Offset 0x38
    uint64_t usn;                // Offset 0x40
} __attribute__((packed)) Standard_Info_Value;

// $FILE_NAME (Type 0x30) Value - Variable size
typedef struct {
    uint64_t parent_directory_ref; // Offset 0x00: Reference to parent MFT record
    uint64_t creation_time;      // Offset 0x08
    uint64_t last_mft_change;    // Offset 0x10
    uint64_t last_access_time;   // Offset 0x18
    uint64_t last_mod_time;      // Offset 0x20
    uint64_t allocated_size;     // Offset 0x28
    uint64_t real_size;          // Offset 0x30
    uint32_t flags;              // Offset 0x38 (e.g., Read-only, Hidden)
    uint32_t reparse_point_tag;  // Offset 0x3C
    uint8_t filename_length;     // Offset 0x40
    uint8_t filename_namespace;  // Offset 0x41 (0=POSIX, 1=Win32, 2=DOS, 3=Win32/DOS)
    // Filename follows at offset 0x42 (and is UTF-16LE)
} __attribute__((packed)) File_Name_Value;


// --- 4. Attribute Type Lookup Table ---
typedef struct {
    uint32_t code;
    const char *name;
} AttributeType;

const AttributeType attribute_types[] = {
    {0x10, "$STANDARD_INFORMATION"},
    {0x20, "$ATTRIBUTE_LIST"},
    {0x30, "$FILE_NAME"},
    {0x40, "$VOLUME_VERSION"},
    {0x50, "$SECURITY_DESCRIPTOR"},
    {0x60, "$VOLUME_NAME"},
    {0x70, "$VOLUME_INFORMATION"},
    {0x80, "$DATA"},
    {0x90, "$INDEX_ROOT"},
    {0xA0, "$INDEX_ALLOCATION"},
    {0xB0, "$BITMAP"},
    {0xC0, "$REPARSE_POINT"},
    {0xFFFFFFFF, "End of Attributes"}
};

// --- Utility Functions ---

/**
 * @brief Converts raw NTFS time (100ns since 1601) to human-readable format with microsecond precision.
 */
void print_human_time(const char *label, uint64_t ntfs_time) {
    if (ntfs_time == 0) {
        printf("    %-24s: N/A\n", label);
        return;
    }

    // 1. Calculate the total 100ns intervals since 1970
    uint64_t total_100ns = ntfs_time - EPOCH_DIFFERENCE;
    
    // 2. Calculate the whole seconds part (10,000,000 * 100ns intervals per second)
    time_t seconds = (time_t)(total_100ns / 10000000ULL);

    // 3. Calculate the fractional part (remaining 100ns intervals)
    uint64_t fractional_100ns = total_100ns % 10000000ULL;

    // Convert to UTC time structure
    struct tm *tm_info = gmtime(&seconds);
    
    char buffer[100];
    char time_str[130];
    
    // Format the standard date/time part
    strftime(buffer, 100, "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Append the fractional part with 6 digits (microsecond precision)
    // We print 7 digits of the 100ns interval, then cap at 6 decimal places.
    snprintf(time_str, sizeof(time_str), "%s.%07llu UTC", 
             buffer, (unsigned long long)fractional_100ns);
    
    // Print the result, trimming the 7th digit to display 6 decimal places.
    // E.g., 2025-11-18 01:08:02.1234567 UTC -> 2025-11-18 01:08:02.123456 UTC
    time_str[strlen(buffer) + 7] = ' '; 

    printf("    %-24s: %s\n", label, time_str);
}

/**
 * @brief Translates an Attribute Type Code into a human-readable name.
 */
const char* get_attribute_name(uint32_t code) {
    size_t table_size = sizeof(attribute_types) / sizeof(attribute_types[0]);
    for (size_t i = 0; i < table_size; ++i) {
        if (attribute_types[i].code == code) {
            return attribute_types[i].name;
        }
    }
    return "Unknown Attribute";
}

/**
 * @brief Reads a variable-length integer (up to 8 bytes) from a byte stream.
 */
int64_t read_variable_length_int(const uint8_t *data, uint8_t length, int is_signed) {
    int64_t value = 0;
    
    if (length == 0 || length > 8) return 0;
    
    // Read bytes in little-endian order
    for (int i = 0; i < length; ++i) {
        value |= (int64_t)data[i] << (i * 8);
    }

    // Handle sign extension if requested and necessary (only for the LCN delta)
    if (is_signed && (data[length - 1] & 0x80)) {
        // Sign extend the value to 64 bits
        for (int i = length; i < 8; ++i) {
            value |= (int64_t)0xFF << (i * 8);
        }
    }

    return value;
}


/**
 * @brief Parses the Data Runs list for a Non-Resident attribute.
 */
void parse_data_runs(const uint8_t *data_run_start, uint32_t run_offset, uint32_t offset_limit) {
    const uint8_t *current_run = data_run_start;
    uint32_t run_index = 0;
    int64_t previous_lcn = 0; // Accumulator for LCN delta

    printf("      --- Data Runs (VCN to LCN Mapping) ---\n");
    printf("      Run # | Length (Clus) | Start LCN (Disk Loc)\n");
    printf("      ------+---------------+----------------------\n");

    while (*current_run != 0x00 && (current_run - data_run_start) < (offset_limit - run_offset)) {
        uint8_t header_byte = *current_run;
        uint8_t lcn_length = header_byte >> 4;       // Length of the LCN field (M)
        uint8_t length_length = header_byte & 0x0F;  // Length of the Run Length field (N)
        
        current_run++; // Move past the header byte

        if (length_length == 0 || lcn_length > 8 || length_length > 8) {
            printf("      [ERROR: Invalid run header byte 0x%02X. Stopping runs parse.]\n", header_byte);
            return;
        }

        // 1. Read the Run Length (N bytes)
        int64_t run_length = read_variable_length_int(current_run, length_length, 0);
        current_run += length_length;

        // 2. Read the LCN Delta (M bytes - can be 0 for sparse data)
        int64_t lcn_delta = 0;
        if (lcn_length > 0) {
            // LCN is a delta relative to the previous run's LCN. It MUST be signed.
            lcn_delta = read_variable_length_int(current_run, lcn_length, 1); 
            current_run += lcn_length;
        }

        // Calculate the absolute LCN
        int64_t current_lcn = 0;
        if (lcn_length > 0) {
            current_lcn = previous_lcn + lcn_delta;
            previous_lcn = current_lcn;
        }
        
        // Print the run details
        char lcn_str[21];
        if (lcn_length == 0) {
            snprintf(lcn_str, sizeof(lcn_str), "Sparse/Unallocated");
        } else if (current_lcn == 0) {
            snprintf(lcn_str, sizeof(lcn_str), "0 (Sparse/Zeroed)");
        } else if (current_lcn > 0) {
            snprintf(lcn_str, sizeof(lcn_str), "%llu", (unsigned long long)current_lcn);
        } else {
            snprintf(lcn_str, sizeof(lcn_str), "ERROR LCN");
        }

        printf("      %5u | %13llu | %20s\n", 
               ++run_index, 
               (unsigned long long)run_length, 
               lcn_str);
    }
}


// --- Attribute Decoding Functions (One per Type) ---

/**
 * @brief Decodes and prints the $STANDARD_INFORMATION (0x10) attribute value.
 */
void decode_standard_information(const MFT_Attribute_Header *attr_header, const uint8_t *value_start) {
    const Standard_Info_Value *std_info = (const Standard_Info_Value*)value_start;

    printf("    -- $STANDARD_INFORMATION Details --\n");
    print_human_time("Creation Time", std_info->creation_time);
    print_human_time("Last MFT Change", std_info->last_mft_change);
    print_human_time("Last Access Time", std_info->last_access_time);
    print_human_time("Last Data Mod Time", std_info->last_mod_time);
    printf("    DOS Permissions (Flags):  0x%08X\n", std_info->dos_permissions);
    
    // Check common flags
    if (std_info->dos_permissions & 0x01) printf("      -> Read-Only\n");
    if (std_info->dos_permissions & 0x02) printf("      -> Hidden\n");
    if (std_info->dos_permissions & 0x04) printf("      -> System\n");
    if (std_info->dos_permissions & 0x10) printf("      -> Directory\n");
    if (std_info->dos_permissions & 0x20) printf("      -> Archive\n");
    if (std_info->dos_permissions & 0x40) printf("      -> Device\n");
}

/**
 * @brief Decodes and prints the $FILE_NAME (0x30) attribute value.
 */
void decode_file_name(const MFT_Attribute_Header *attr_header, const uint8_t *value_start) {
    const File_Name_Value *fn_value = (const File_Name_Value*)value_start;
    
    // Filename starts at offset 0x42 from the value start
    const uint16_t *filename_utf16 = (const uint16_t*)(value_start + 0x42);
    char filename_buffer[256] = {0};
    
    // Convert UTF-16LE to simple ASCII (taking every second byte)
    for (int i = 0; i < fn_value->filename_length && i < 127; i++) {
        filename_buffer[i] = (char)(filename_utf16[i] & 0xFF);
    }

    printf("    -- $FILE_NAME Details --\n");
    printf("    Filename:                 %s\n", filename_buffer);
    printf("    Filename Length:          %u (in UTF-16 chars)\n", fn_value->filename_length);
    printf("    Namespace:                %u\n", fn_value->filename_namespace);
    printf("    Parent MFT Record:        %llu\n", (unsigned long long)(fn_value->parent_directory_ref & 0x0000FFFFFFFFFFFFULL));
    
    // All four timestamps in the $FILE_NAME attribute (Crucial for timeline analysis)
    print_human_time("Creation Time (FN)", fn_value->creation_time);
    print_human_time("Last MFT Change (FN)", fn_value->last_mft_change);
    print_human_time("Last Access Time (FN)", fn_value->last_access_time);
    print_human_time("Last Data Mod Time (FN)", fn_value->last_mod_time);

    printf("    Real Size:                %llu bytes\n", (unsigned long long)fn_value->real_size);
}

/**
 * @brief Decodes and prints the $DATA (0x80) attribute.
 */
void decode_data_attribute(const MFT_Attribute_Header *attr_header, const uint8_t *current_position, const uint8_t *value_start) {
    const MFT_Attribute_Header *h = attr_header;
    const struct { /* Anonymous structure for non_resident details access */
        uint64_t starting_vcn;
        uint64_t ending_vcn;
        uint16_t data_runs_offset;
        uint16_t compression_unit;
        uint32_t reserved_padding;
        uint64_t allocated_size;
        uint64_t real_size;
        uint64_t initialized_size;
        uint64_t compressed_size;
    } *nr = &h->details.non_resident; // Pointer assignment simplified

    printf("    -- $DATA Attribute Details --\n");
    
    // Check for Alternate Data Stream Name
    if (h->name_length > 0) {
        // Stream name is stored as UTF-16LE string starting at name_offset
        const uint16_t *stream_name_utf16 = (const uint16_t*)(current_position + h->name_offset);
        char stream_name_buffer[256] = {0};

        // Convert UTF-16LE to simple ASCII
        for (int i = 0; i < h->name_length && i < 127; i++) {
            stream_name_buffer[i] = (char)(stream_name_utf16[i] & 0xFF);
        }
        
        printf("    Stream Name:              :%s\n", stream_name_buffer);
        printf("    Stream Name Length:       %u (in UTF-16 chars)\n", h->name_length);
        printf("    **This is an Alternate Data Stream (ADS).**\n");
    } else {
        printf("    **This is the Primary Data Stream ($DATA).**\n");
    }


    if (h->non_resident == 0) {
        // Resident $DATA: Content is inside the MFT record
        printf("    Resident Value Length:    %u bytes\n", h->details.resident.value_length);
        
        if (h->details.resident.value_length > 0) {
            printf("    Content stored directly in MFT record.\n");
        } else {
            printf("    Value is empty or zero-length.\n");
        }

    } else {
        // Non-Resident $DATA: Content is elsewhere on the disk
        
        printf("    Starting VCN:             %llu\n", (unsigned long long)nr->starting_vcn);
        printf("    Ending VCN:               %llu\n", (unsigned long long)nr->ending_vcn);
        printf("    Data Run Offset:          %u\n", nr->data_runs_offset);
        
        // --- COMPLETE NON-RESIDENT FIELDS ---
        printf("    Compression Unit:         %u (log base 2)\n", nr->compression_unit);
        printf("    Allocated Size:           %llu bytes\n", (unsigned long long)nr->allocated_size);
        printf("    Real Data Size:           %llu bytes\n", (unsigned long long)nr->real_size);
        printf("    Initialized Size:         %llu bytes\n", (unsigned long long)nr->initialized_size);
        
        if (h->flags & 0x0001) { // Check for compressed flag (0x0001)
            printf("    Compressed Size:          %llu bytes\n", (unsigned long long)nr->compressed_size);
            printf("    -> ATTRIBUTE IS COMPRESSED\n");
        } else {
            printf("    Compressed Size:          N/A\n");
        }
        
        // --- Parse Data Runs ---
        const uint8_t *data_run_start = current_position + nr->data_runs_offset;
        parse_data_runs(data_run_start, nr->data_runs_offset, h->length);
    }
}

/**
 * @brief Decodes and prints non-resident attributes we haven't implemented specific decoding for.
 */
void decode_non_resident_generic(const MFT_Attribute_Header *attr_header, const uint8_t *current_position) {
    const MFT_Attribute_Header *h = attr_header;
    const struct { /* Anonymous structure for non_resident details access */
        uint64_t starting_vcn;
        uint64_t ending_vcn;
        uint16_t data_runs_offset;
        uint16_t compression_unit;
        uint32_t reserved_padding;
        uint64_t allocated_size;
        uint64_t real_size;
        uint64_t initialized_size;
        uint64_t compressed_size;
    } *nr = &h->details.non_resident; // Pointer assignment simplified

    printf("    -- Non-Resident Attribute Details --\n");
    printf("    Starting VCN:             %llu\n", (unsigned long long)nr->starting_vcn);
    printf("    Ending VCN:               %llu\n", (unsigned long long)nr->ending_vcn);
    printf("    Data Run Offset:          %u\n", nr->data_runs_offset);
    printf("    Allocated Size:           %llu bytes\n", (unsigned long long)nr->allocated_size);

    // For generic non-resident types, we also parse the data runs if they exist
    if (nr->data_runs_offset != 0) {
        const uint8_t *data_run_start = current_position + nr->data_runs_offset;
        parse_data_runs(data_run_start, nr->data_runs_offset, h->length);
    }
}

/**
 * @brief Generic handler for attributes we haven't implemented specific decoding for.
 */
void decode_generic(const MFT_Attribute_Header *attr_header) {
    printf("    -- Generic Attribute Details --\n");
    printf("    No specific decoder implemented for this type.\n");
    // Print common residential details if applicable
    if (attr_header->non_resident == 0) {
        printf("    Value Length:             %u bytes\n", attr_header->details.resident.value_length);
        printf("    Value Offset:             %u\n", attr_header->details.resident.value_offset);
    }
}

// --- Main Parsing Logic ---

/**
 * @brief Reads a 1024-byte MFT Record from stdin and prints header and attribute details.
 */
int main() {
    uint8_t raw_mft_data[MFT_RECORD_SIZE];
    MFT_Record_Header *header;
    size_t bytes_read;
    uint8_t *current_position;

    // 1. Read the MFT Record block from standard input
    bytes_read = fread(raw_mft_data, 1, MFT_RECORD_SIZE, stdin);

    if (bytes_read != MFT_RECORD_SIZE) {
        fprintf(stderr, "Error: Could not read 1024 bytes for MFT record. Read %zu bytes.\n", bytes_read);
        fprintf(stderr, "Ensure you are piping the full 1024-byte MFT record.\n");
        return EXIT_FAILURE;
    }
    
    // Fixup application (Skipped for simplicity, but assumed correct data is piped)
    header = (MFT_Record_Header*)raw_mft_data;

    // 2. Verify the MFT signature
    if (header->signature != MFT_SIGNATURE) {
        fprintf(stderr, "Error: Invalid MFT Signature. Expected 'FILE' (0x%X), found 0x%X.\n", 
                MFT_SIGNATURE, header->signature);
        return EXIT_FAILURE;
    }

    printf("MFT Signature Check: OK ('FILE')\n");
    printf("\n--- MFT Record Header Details ---\n");
    
    // 3. Print key header details
    printf("  MFT Record Number:        %u\n", header->mft_record_number);
    printf("  Sequence Number:          %u\n", header->sequence_number);
    printf("  Record Flags:             0x%04X (%s)\n", header->flags,
           (header->flags & 0x0001) ? "IN USE" : "DELETED");
    printf("  First Attribute Offset:   %u\n", header->first_attribute);
    printf("  Real Data Size:           %u bytes\n", header->real_size);

    printf("\n--- Attribute List ---\n");
    
    // 4. Iterate through all attributes
    current_position = (uint8_t*)header + header->first_attribute;
    int attr_index = 0;

    while (current_position < raw_mft_data + header->real_size) {
        MFT_Attribute_Header *attr_header = (MFT_Attribute_Header*)current_position;
        
        if (attr_header->type_code == 0xFFFFFFFF) {
            printf("\n  [End of Attributes Marker Reached]\n");
            break;
        }

        // Basic sanity check
        if (attr_header->length == 0 || (current_position + attr_header->length) > (raw_mft_data + MFT_RECORD_SIZE)) {
            printf("\n  [ERROR: Invalid attribute length (%u) at offset %lu. Stopping parse.]\n", 
                   attr_header->length, (unsigned long)(current_position - raw_mft_data));
            break;
        }

        // --- Attribute Summary ---
        printf("\n  Attribute %d: %s (0x%X)\n", 
               ++attr_index, get_attribute_name(attr_header->type_code), attr_header->type_code);
        printf("    Total Length:             %u bytes\n", attr_header->length);
        printf("    Is Resident:              %s\n", attr_header->non_resident ? "NO (Non-Resident)" : "YES (Resident)");
        
        // 5. Dispatch to dedicated decoding function
        uint8_t *value_start = NULL;
        if (attr_header->non_resident == 0) {
            // Only resident attributes have a value_start pointer
            value_start = current_position + attr_header->details.resident.value_offset;
            printf("    Value Length:             %u bytes\n", attr_header->details.resident.value_length);
            printf("    Value Offset:             %u\n", attr_header->details.resident.value_offset);
        }

        switch (attr_header->type_code) {
            case 0x10: // $STANDARD_INFORMATION
                decode_standard_information(attr_header, value_start);
                break;
            case 0x30: // $FILE_NAME
                decode_file_name(attr_header, value_start);
                break;
            case 0x80: // $DATA
                decode_data_attribute(attr_header, current_position, value_start);
                break;
            case 0xB0: // $BITMAP
            case 0x20: // $ATTRIBUTE_LIST
                // These are typically non-resident and require data run parsing
                if (attr_header->non_resident != 0) {
                    decode_non_resident_generic(attr_header, current_position);
                } else {
                    decode_generic(attr_header);
                }
                break;
            default:
                decode_generic(attr_header);
                break;
        }

        // Move to the next attribute (aligned to 8-byte boundary)
        current_position += attr_header->length;
        // NTFS attributes are 8-byte aligned
        current_position = (uint8_t*)(((uintptr_t)current_position + 7) & ~7); 
    }

    printf("-----------------------------------------\n");

    return EXIT_SUCCESS;
}
