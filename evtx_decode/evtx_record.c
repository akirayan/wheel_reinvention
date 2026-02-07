/* evtx_record.c
 *
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>


#include "evtx_output.h"

#include "hex_dump.h"
#include "timestamp.h"
#include "utf16le.h"

#include "evtx_chunk.h"
#include "evtx_record.h"
#include "evtx_binxml.h"


// substitution value array
typedef struct {
    uint16_t size;          // raw value size
    uint16_t type;          // EVTX value type
    uint32_t value_offset;  // relative offset in chunk_buffer
} EVTX_VALUE_ITEM;

typedef struct {
    uint16_t count;
    EVTX_VALUE_ITEM *items;
} EVTX_VALUE_TABLE;


// find the offset for template definition header
static uint32_t get_template_def_offset(uint8_t *chunk_buffer, uint32_t record_base) 
{
    // [24B Record Header] + [4B BinXML Header] + [0x0C Token]
    uint8_t *token_0c_ptr = &chunk_buffer[record_base + 24 + 4];

    if (*token_0c_ptr == 0x0c) {
        // Token(1B) + Unknown(1B) + TemplateID(4B) + Offset(4B)
        return *(uint32_t *)(token_0c_ptr + 6);
    }
    return 0;
}

// Template Definition Header
static EVTX_TEMPLATE_DEFINITION_HEADER *get_template_def_header(uint8_t *chunk_buffer, uint32_t record_base) 
{
    EVTX_TEMPLATE_DEFINITION_HEADER *th = (EVTX_TEMPLATE_DEFINITION_HEADER *)0x00;
    uint32_t def_offset = get_template_def_offset(chunk_buffer, record_base); 
    if (def_offset) {
       th = (EVTX_TEMPLATE_DEFINITION_HEADER *)&chunk_buffer[def_offset];
    }
    return th;
}

// item_count (4バイト) が格納されているPOSITIONを返す
static uint32_t get_value_table_position(uint8_t *chunk_buffer, uint32_t record_base) 
{
    uint32_t def_offset = get_template_def_offset(chunk_buffer, record_base); 

    // 0x0Cトークン(1B) + Flag(1B) + ID(4B) + Offset(4B) = 10バイト
    uint32_t after_token_offset = record_base + + sizeof(EVTX_RECORD_HEADER) + 4 + 10; // チャンク内相対アドレス

    if (after_token_offset == def_offset) {
        // Case 1: Inline Definition (すぐ後ろに金型がある)
        // [Header 24B] + [BinXML size] の後に item_count が来る
        EVTX_TEMPLATE_DEFINITION_HEADER *th = get_template_def_header(chunk_buffer, record_base);
        return after_token_offset + sizeof(EVTX_TEMPLATE_DEFINITION_HEADER) + th->data_size;  
    } else {
        // Case 2: Reference (金型は別の場所)
        // 0x0C構造のすぐ後ろに item_count が来る
        return after_token_offset;
    }
}





// hide the object
static EVTX_VALUE_TABLE *get_value_table()
{
    static EVTX_VALUE_TABLE my_table;
    return &my_table;
}



// build the TABLE, set each member from chunk_buffer
static void create_value_table(uint8_t *chunk_buffer, uint32_t item_count_position)
{
    // data layout verified working!!!
    // 4B item_count           at item_count_position
    // 2B size for %0          at item_count_position + 4 * 0
    // 2B type for %0          at item_count_position + 4 * 0 + 2
    // 2B size for %0          at item_count_position + 4 * 1
    // 2B type for %0          at item_count_position + 4 * 1 + 2
    // .... for each %#
    // 2B size for %count-1
    // 2B type for %count-1
    // data for %0 (offset for %1)  at item_count_position + 4 + 4 * count
    // data for %1 (offset for %2)  at item_count_position + 4 + 4 * count + size0
    // data for %2 (offset for %2)  at item_count_position + 4 + 4 * count + size0 + size1

    EVTX_VALUE_TABLE *tbl = get_value_table();
    uint32_t count = *(uint32_t *)(chunk_buffer + item_count_position);
    tbl->count = count;
    tbl->items = calloc(count, sizeof(EVTX_VALUE_ITEM));

    uint32_t off = item_count_position + 4 + count * 4; // skip count itself and 4B for each

    for (uint32_t i = 0; i < count; i++) {
        uint16_t size = *(uint16_t *)(chunk_buffer + item_count_position + 4 + i * 4);
        uint16_t type = *(uint16_t *)(chunk_buffer + item_count_position + 4 + i * 4 + 2);

        tbl->items[i].size = size;
        tbl->items[i].type = type;
        tbl->items[i].value_offset = off;

        // uint32_t value_len = calc_value_len(size, type);
        uint32_t value_len = size; // trust the size
        off += value_len;
    }
}

// free the allocated memory
static void delete_value_table()
{
    EVTX_VALUE_TABLE *tbl = get_value_table();
    free(tbl->items);
}





static void print_evtx_filetime(uint64_t filetime) {
    // 100-nanosecond intervals between 1601 and 1970
    const uint64_t EPOCH_DIFF = 116444736000000000ULL;
    
    uint64_t unix_intervals = filetime - EPOCH_DIFF;
    time_t seconds = (time_t)(unix_intervals / 10000000ULL);
    uint32_t nanoseconds = (uint32_t)((unix_intervals % 10000000ULL) * 100);

    struct tm *utc_time = gmtime(&seconds);
    
    // Format: YYYY-MM-DDTHH:MM:SS.ssssssZ
    printf("%04d-%02d-%02dT%02d:%02d:%02d.%09uZ",
           utc_time->tm_year + 1900, utc_time->tm_mon + 1, utc_time->tm_mday,
           utc_time->tm_hour, utc_time->tm_min, utc_time->tm_sec, nanoseconds);
}



static void print_evtx_sid(uint8_t *sid_ptr) {
    if (!sid_ptr) return;

    // Byte 0: Revision (S-n)
    uint8_t revision = sid_ptr[0];

    // Byte 1: Sub-Authority Count (How many 4-byte chunks follow)
    uint8_t sub_auth_count = sid_ptr[1];

    // Bytes 2-7: Identifier Authority (6 bytes, Big-Endian)
    // Most common is 00 00 00 00 00 05 (NT Authority)
    uint64_t authority = 0;
    for (int i = 0; i < 6; i++) {
        authority = (authority << 8) | sid_ptr[2 + i];
    }

    // Start printing the SID string
    printf("S-%u-%llu", revision, authority);

    // Bytes 8+: Sub-Authorities (4 bytes each, Little-Endian)
    uint32_t *sub_authorities = (uint32_t *)(sid_ptr + 8);
    for (int i = 0; i < sub_auth_count; i++) {
        printf("-%u", sub_authorities[i]);
    }
    //printf("\n");
}




static void print_evtx_guid(uint8_t *guid_ptr) {
    if (!guid_ptr) return;

    // GUID structure in memory:
    // Data1 (4B, LE), Data2 (2B, LE), Data3 (2B, LE), Data4 (8B, BE/Raw)
    
    uint32_t data1 = *(uint32_t *)&guid_ptr[0];
    uint16_t data2 = *(uint16_t *)&guid_ptr[4];
    uint16_t data3 = *(uint16_t *)&guid_ptr[6];

    printf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
           data1, data2, data3,
           guid_ptr[8], guid_ptr[9],   // Data4 starts here
           guid_ptr[10], guid_ptr[11], 
           guid_ptr[12], guid_ptr[13], 
           guid_ptr[14], guid_ptr[15]);
}


void get_item_value_by_index(uint8_t *chunk_buffer, int index)
{
    EVTX_VALUE_TABLE *tbl = get_value_table();
    if (index >= tbl->count) return;

    EVTX_VALUE_ITEM *val_item = &tbl->items[index];
    uint16_t size = val_item->size;
    uint16_t type = val_item->type;
    uint8_t *data_ptr = chunk_buffer + val_item->value_offset;

    // Handle empty values (like your %13)
    if (size == 0 && type != 0x00) {
        printf("[Empty]");
        return;
    }

    switch (type) {
        case 0x00: // NullType
            printf("(null)");
            break;

        case 0x01: // StringType (Unicode UTF-16LE)
            // We pass the size in bytes to our helper
            print_utf16le_string(size/2, (uint16_t *)data_ptr);
            break;

        case 0x02: // AnsiStringType
            printf("%.*s", size, (char *)data_ptr);
            break;

        case 0x04: // Uint32Type (Your debug says Uint8, but 0x04 is usually 32-bit)
            if (size == 1) printf("%u", *data_ptr);
            else if (size == 4) printf("%u", *(uint32_t *)data_ptr);
            break;

       case 0x06: // Uint16Type
           if (size == 2) printf("%u", *(uint16_t *)data_ptr);
           break;

        case 0x08: // Uint32Type in your table (standard is 64-bit, let's follow your size)
            if (size == 4) printf("%u", *(uint32_t *)data_ptr);
            else if (size == 8) printf("%llu", *(uint64_t *)data_ptr);
            break;

        case 0x0A: // Uint64Type
            printf("%llu", *(uint64_t *)data_ptr);
            break;

        case 0x0F: // GuidType
            print_evtx_guid(data_ptr);
            break;

        case 0x11: // FileTimeType
            print_evtx_filetime(*(uint64_t *)data_ptr);
            break;

        case 0x13: // SidType (0x13 or 0x1C depending on version)
            print_evtx_sid(data_ptr);
            break;

        case 0x15: // HexInt64Type
            printf("0x%016llx", *(uint64_t *)data_ptr);
            break;

        case 0x21: // BinXmlType
        {
            printf("[Embedded BinXML Area - %d bytes]", size);
            BinXmlContext sub_ctx = {
                .chunk_buffer = chunk_buffer,
                .data_ptr = chunk_buffer + val_item->value_offset,
                .end_ptr  = chunk_buffer + val_item->value_offset + val_item->size,
            };


            // dump it 
            printf("\n");
            hex_dump_bytes(chunk_buffer + val_item->value_offset, val_item->size);

            printf("call from get_item_value_by_index()\t");
            // decode it
            decode_binxml(chunk_buffer, val_item->value_offset, val_item->size); 

            // parse_binxml_stream(&sub_ctx);
            break;
       }






        default:
            printf("[Unknown Type 0x%02x, size %d]", type, size);
            break;
    }
}















int decode_evtx_record(uint32_t chunk_base, uint32_t record_base, uint8_t *chunk_buffer, uint16_t output_mode)
{
    // the stuct to hold the record header
    EVTX_RECORD_HEADER *rh = (EVTX_RECORD_HEADER *) &chunk_buffer[record_base]; 
    
    // verify record signature at here
    if (rh->signature != EVTX_RECORD_SIGNATURE) {
        fprintf(stderr, "ERROR: invalid record signature at 0x%" PRIx32 "\n", record_base);
        return 1;   // this chunk is broken, ignore remained records
    }
    // check if record corrupted.
    if (rh->record_size <= sizeof(EVTX_RECORD_HEADER) + 4) { 
        return 2;
    }

    // convert timestamp to ISO format
    char time_written[32]; // Timestamp of writting to evtx file
    format_filetime(rh->timestamp, time_written, sizeof(time_written));

    // print summary of the event
    printf("ElfRec#%06" PRIu64 " (0x%08" PRIx32 ")\t%s\tsize=%" PRIu32 "\n",
            rh->record_identifier,
            chunk_base + record_base,
            time_written,
            rh->record_size 
            );

    // dump the whole record
    if (output_mode & OUTPUT_DUMP) {
        hex_dump_bytes(&chunk_buffer[record_base], rh->record_size);
    }

    // decode binxml 
    uint32_t binxml_offset = record_base + sizeof(EVTX_RECORD_HEADER);
    uint32_t binxml_size = rh->record_size - sizeof(EVTX_RECORD_HEADER) - sizeof(uint32_t); 
                               // the lastt 4B is record_size_COPY, so we do not calculate it 

    // decode it
    //printf("DEBUG: called from decode_evtx_record()\t"); 
    decode_binxml(chunk_buffer, binxml_offset, binxml_size);

    return 0;
}


