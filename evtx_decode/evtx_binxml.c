
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "evtx_chunk.h"
#include "evtx_record.h"
#include "evtx_binxml.h"
#include "evtx_output.h"

#include "utf16le.h"
#include "timestamp.h"
#include "hex_dump.h"
#include "stack.h"



#pragma pack(push, 1)

// Token 0x0f: BINXML Fragment
typedef struct {
    uint8_t  token;          // should be 0x0f
    uint8_t  major_version;     // e.g., 0x01 for String, 0x04 for Hex32, etc.
    uint8_t  minor_version;     // e.g., 0x01 for String, 0x04 for Hex32, etc.
    uint8_t  flag;     // e.g., 0x01 for String, 0x04 for Hex32, etc.
                             // followed by the actual data based on the type
} TOKEN_0F_FRAGMENT_HEADER;

// Token 0x01 / 0x41: Open Element
typedef struct {
    uint8_t  token;          // should be 0x01 or 0x41
    uint16_t dependency_id;  // Usually 0xFFFF
    uint32_t element_size;   // Total size of this element branch
    uint32_t name_offset;    // Offset to Name Descriptor
                             // for 0x41: 4B as more_data_size 
} TOKEN_01_OPEN_ELEMENT_HEADER;

// Token 0x05: Value Token
typedef struct {
    uint8_t  token;          // should be 0x05
    uint8_t  value_type;     // e.g., 0x01 for String, 0x04 for Hex32, etc.
                             // followed by the actual data based on the type
} TOKEN_05_ATTRIBUTE_VALUE_HEADER;

// Token 0x06 / 0x46: Attribute Name
typedef struct {
    uint8_t  token;          // should be 0x06 or 0x46
    uint32_t name_offset;    // name offfset for Attribute Name
                             // NOTE for 0x46: NO MORE 4B as more_data_size 
} TOKEN_06_ATTRIBUTE_NAME_HEADER;


// Token 0x36: Attribute Name   (new token found by me)
typedef struct {
    uint8_t  token;          // should be 0x36
    uint8_t  unknown[4];     // Unknown/Dependency ID. Similar to the ff ff seen in 0x41, but 4 bytes. 
                             // This might be a more complex dependency identifier.
    uint32_t name_offset;    // name offfset for Attribute Name
} TOKEN_36_ATTRIBUTE_NAME_HEADER;







// Token 0x0d BinXmlTokenNormalSubstitution 
// Token 0x0e BinXmlTokenOptionallSubstitution
typedef struct {
    uint8_t  token;      // should be 0x0d or 0x0e
    uint16_t subs_id;    // Substitution identifier
    uint8_t value_type;    
} TOKEN_0E_SUBSTITUTION_HEADER;

// Token 0x0C: Template Instance Header
// the 33-byte structure including 24-byte of TEMPLATE_DEFINITION_HEADER
// now I use the 9-byte structure only
typedef struct {
    uint8_t  unknown_val;         // unknown but usually seen as 0x01
    uint32_t template_id;      // the template ID as same as template_id
    uint32_t template_offset;   // offset to TEMPLATE_DEFINITION_HEADER, usually next 4 bytes
} BINXML_TEMPLATE_INSTANCE_HEADER;

// substitution value array
typedef struct {
    uint16_t size;          // raw value size
    uint16_t type;          // EVTX value type, only 1 byte used
    uint32_t value_offset;  // relative offset in chunk_buffer
} EVTX_VALUE_ITEM;

typedef struct {
    uint16_t count;
    EVTX_VALUE_ITEM *items;
} EVTX_VALUE_TABLE;

#pragma pack(pop)


static void print_value_by_index(EVTX_VALUE_TABLE *tbl, uint8_t *chunk_buffer, uint32_t index, uint32_t output_mode, XML_TREE *xtree);


const char* get_value_type_name(uint8_t value_type) {
    switch (value_type) {
        case 0x00: return "NullType";
        case 0x01: return "Utf16le";
        case 0x02: return "AnsiString";
        case 0x03: return "Int8Type";
        case 0x04: return "Uint8Type";
        case 0x05: return "Int16Type";
        case 0x06: return "Uint16Type";
        case 0x07: return "Int32Type";
        case 0x08: return "Uint32Type";
        case 0x09: return "Int64Type";
        case 0x0a: return "Uint64Type";
        case 0x0b: return "Real32Type";
        case 0x0c: return "Real64Type";
        case 0x0d: return "BoolType";
        case 0x0e: return "BinaryType";
        case 0x0f: return "GuidType";
        case 0x10: return "SizeTType";
        case 0x11: return "FileTime";
        case 0x12: return "SysTime";
        case 0x13: return "SidType";
        case 0x14: return "HexInt32";
        case 0x15: return "HexInt64";
        case 0x20: return "EvtHandle";
        case 0x21: return "BinXmlType";
        case 0x23: return "EvtXml";
        default: 
            // 0x80 フラグが立っている場合は配列型
            if (value_type & 0x80) return "ArrayType";
            return "UnknownType";
    }
}




/**
 * インラインの名前エントリが存在する場合、そのサイズを計算して返す。
 *
 * @param buffer  BinXMLのバッファ
 * @param pos     現在の読み込み位置（NameOffsetの直後の位置）
 * @param name_off 解析したNameOffset
 * @return スキップすべきバイト数（実体がない場合は0）
 */
static uint32_t get_inline_name_skip_bytes(uint8_t *chunk_buffer, uint32_t cursor_offset, uint32_t name_offset) 
{
    uint32_t skip_size = 0;

    //printf("DEBUG: get_inline_name_skip_bytes() cursor=0x%x\tname_offset=0x%x", cursor_offset, name_offset);

    if (cursor_offset == name_offset) { 
        // Name_Offset is just at the cursor, need to skip it
        EVTX_NAME_ENTRY_HEADER nh;
        memcpy(&nh, &chunk_buffer[cursor_offset], sizeof(nh));

        skip_size = sizeof(nh) + (nh.char_count * 2 + 2); // plus 2 NULLs
    }

    //printf("\tskip_size=%d\n", skip_size);

    return skip_size;
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

    printf("{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
           data1, data2, data3,
           guid_ptr[8], guid_ptr[9],   // Data4 starts here
           guid_ptr[10], guid_ptr[11], 
           guid_ptr[12], guid_ptr[13], 
           guid_ptr[14], guid_ptr[15]);
}

// build the TABLE, set each member from chunk_buffer
static void create_value_table(EVTX_VALUE_TABLE *tbl, uint8_t *chunk_buffer, uint32_t value_table_offset, uint32_t output_mode)
{
    // value_array layout
    // 4B item_count    at value_table_offset
    // 2B size %0   at value_table_offset + 4 * 0
    // 1B type %0   at value_table_offset + 4 * 0 + 2
    // 2B size %1   at value_table_offset + 4 * 1
    // 2B type %1   at value_table_offset + 4 * 1 + 2
    // ....         repeat for all item_count
    // data %0      at value_table_offset + 4 + 4 * count
    // data %1      at value_table_offset + 4 + 4 * count + size0
    // data %2      at value_table_offset + 4 + 4 * count + size0 + size1
    // .... until to last item

    uint32_t count = *(uint32_t *)(chunk_buffer + value_table_offset);
    tbl->count = count;
    tbl->items = calloc(count, sizeof(EVTX_VALUE_ITEM));

    // the offset of data %0
    uint32_t value_offset = value_table_offset + sizeof(count) + count * 4; 

    for (uint32_t i = 0; i < count; i++) {
        uint16_t size = *(uint16_t *)(chunk_buffer + value_table_offset + sizeof(count) + i * 4); 
        uint16_t type = *(uint16_t *)(chunk_buffer + value_table_offset + sizeof(count) + i * 4 + 2); 

        tbl->items[i].size = size;
        tbl->items[i].type = type;
        tbl->items[i].value_offset = value_offset;

        value_offset += size; // trust the size
    }

}

// free the allocated memory
static void delete_value_table(EVTX_VALUE_TABLE *tbl)
{
    free(tbl->items);
}

// get the value by index
static void print_value_by_index(EVTX_VALUE_TABLE *tbl, 
                                  uint8_t *chunk_buffer, 
                                  uint32_t index, 
                                  uint32_t output_mode, 
                                  XML_TREE *xtree)
{
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
            printf("0x%llx", *(uint64_t *)data_ptr);
            break;

        case 0x21: // BinXmlType
        {
           
            if (CHECK_OUTMODE(output_mode, OUT_DEBUG)) {
                printf("[Embedded BinXML Area - %d bytes]", size);
                printf("\nDEBUG: called from print_value_by_index()\t");
            }

            // decode it
            decode_binxml(chunk_buffer, val_item->value_offset, val_item->size, output_mode, xtree); 

            break;
       }

       default:
           printf("[Unknown Type 0x%02x, size %d]", type, size);
           break;
    }
}






static void decode_template_with_values(
                   uint8_t *chunk_buffer,        /* the 64KB chunk in memory */
                   uint32_t binxml_offset,       /* start position of binxml, related to chunk_buffer */
                   uint32_t binxml_size,         /* the size of buffer =  record_size - 24 - 4  */       
                   EVTX_VALUE_TABLE *tbl_ptr,    /* value table of this binxml */
                   uint32_t output_mode,         /* CSV or DEBUG etc */
                   XML_TREE *xtree)              /* the tree */
{
    uint32_t i = binxml_offset;  // the starting point of cursor in buffer
    uint32_t binxml_limit = binxml_offset + binxml_size;  // the hard limit of cursor in buffer

    XML_TREE *current; // the temprate tree
    STACK *stack = stack_new(); // to hold element names

    if (CHECK_OUTMODE(output_mode, OUT_DEBUG)) {
        printf("DEBUG: decode_template_with_values() offset=0x%08" PRIx32 "\tsize=%" PRIu32 "\n", binxml_offset, binxml_size);
        hex_dump_bytes(&chunk_buffer[binxml_offset], binxml_size);
    }

    while (i < binxml_limit ) {
        uint8_t raw_token = chunk_buffer[i];

        //printf("\nDEBUG: cursor=0x%x\traw_token=0x%02x\n", i, raw_token);
        
        switch (raw_token) {

            case 0x0f: // BinXmlFragmentHeaderToken
            {
                TOKEN_0F_FRAGMENT_HEADER fh;
                memcpy(&fh, &chunk_buffer[i], sizeof(fh));
                i += sizeof(fh); // [Token 1B] [MajorVersion 1B] [MinorVersion 1B] [Flags 1B]
                break;
            }

            case 0x01: // BinXmlTokenOpenStartElement
            case 0x41: // BinXmlTokenOpenStartElement | BinXmlTokenMoreData
            {
                TOKEN_01_OPEN_ELEMENT_HEADER open_el;
                memcpy(&open_el, &chunk_buffer[i], sizeof(open_el));
                i += sizeof(open_el); // skip (Token + DependencyID + DataSize + NameOffset)
            
                char name_buf[1024];
                get_name_from_offset(chunk_buffer, open_el.name_offset, name_buf, sizeof(name_buf));
                printf("<%s", name_buf);
                stack_push(stack, name_buf);

                // if the name_offset is defined at here, skip the whole name buffer
                i += get_inline_name_skip_bytes(chunk_buffer, i, open_el.name_offset);
            
                if (raw_token & 0x40) { 
                    // if token=0x41, there are 4 bytes as attr_list_size
                    // uint32_t attr_list_size = *(uint32_t*)&chunk_buffer[i]; 
                    i += 4; 
                }
            
                break;
            }
            
            case 0x06: // BinXmlTokenAttribute
            case 0x46: // BinXmlTokenAttribute | BinXmlTokenMoreData
            {
                TOKEN_06_ATTRIBUTE_NAME_HEADER attr;
                memcpy(&attr, &chunk_buffer[i], sizeof(attr));
                i += sizeof(attr); // token + 4B 
            
                char name_buf[1024];
                get_name_from_offset(chunk_buffer, attr.name_offset, name_buf, sizeof(name_buf));
                printf(" %s=", name_buf);
            
                // if the name_offset is defined at here, skip the whole name buffer
                i += get_inline_name_skip_bytes(chunk_buffer, i, attr.name_offset);
            
                // NOTE for 0x46
                // there is NO 4 bytes as more_data_size

                break;
            }


            case 0x36: // new token seems for attribute name
            {
                TOKEN_36_ATTRIBUTE_NAME_HEADER attr;
                memcpy(&attr, &chunk_buffer[i], sizeof(attr));
                i += sizeof(attr); // token + 4B unkown + 4B name_offset 
            
                char name_buf[1024];
                get_name_from_offset(chunk_buffer, attr.name_offset, name_buf, sizeof(name_buf));
                printf(" %s=", name_buf);
            
                // if the name_offset is defined at here, skip the whole name buffer
                i += get_inline_name_skip_bytes(chunk_buffer, i, attr.name_offset);
            
                break;
            }


            case 0x05: // BinXmlTokenValue
            case 0x45: // BinXmlTokenValue | BinXmlTokenMoreData
            {
                TOKEN_05_ATTRIBUTE_VALUE_HEADER vh;
                memcpy(&vh, &chunk_buffer[i], sizeof(vh));
                i += sizeof(vh); // token + type

                uint8_t v_type = vh.value_type;
            
                switch (v_type) {
                    case 0x01: // Unicode String
                    {
                        uint16_t char_count = *(uint16_t*)&chunk_buffer[i];
                        i += 2; // consume count

                        print_utf16le_string(char_count, (uint16_t *)&chunk_buffer[i]);
                        i += (char_count * 2); // consume utf16le string

                        break;
                    }

                    case 0x00: // nulltype
                        printf("null");
                        break;

                    default:
                        printf("WARNING: No code for token=0x05 or 0x45: value_type=0x%02x\n", v_type);
                        break;

               }

               // is any thing to handle for 0x45 ??
               break;
            }


            case 0x0d: // BinXmlTokenNormalSubstitution
            case 0x0e: // BinXmlTokenOptionalSubstitution
            {
                TOKEN_0E_SUBSTITUTION_HEADER sh;
                memcpy(&sh, &chunk_buffer[i], sizeof(sh));
                i += sizeof(sh); // token + 2B subID + 1B type

                //printf("DEBUG: subs_id=%%%d\n", sh.subs_id);

                print_value_by_index(tbl_ptr, chunk_buffer, sh.subs_id, output_mode, xtree);

                // how to handle array type?

                break;
            }
            

            case 0x08: // BinXmlTokenCharRef
            case 0x48: // BinXmlTokenCharRef
            case 0x09: // BinXmlTokenEntityRef
            case 0x49: // BinXmlTokenEntityRef
            case 0x07: // BinXmlTokenCDATASection
            case 0x47: // BinXmlTokenCDATASection
            case 0x0a: // BinXmlTokenPITarget
            case 0x0b: // BinXmlTokenCDATASection
                i += 1; // token
                printf("WARNING: no code for this token 0x%02x\n", raw_token);
                break;

            case 0x0c: // BinXmlTokenTemplateInstance
                // this should never appear in template_binxml
                printf("ERROR: Token 0C appreared on template_binxml, something WRONG?\n");
                return;
                break;
            
            case 0x02: // BinXmlTokenCloseStartElementTag
                i += 1;
                printf(">");
                break;

            case 0x03: // BinXmlTokenCloseEmptyElementTag
                i += 1;
                printf("/>\n");
                stack_pop(stack);  // since this is an empty element, we need to pop it from stack, but not print out
                break;

            case 0x04: // BinXmlTokenEndElementTag
                i += 1;
                printf("</%s>\n", stack_pop(stack));
                break;

            case 0x00: // BinXmlTokenEOF  EOF or Padding, just skip it to next byte
                i += 1;
                break;

            default:
                printf("WARNING: Token 0x%02x NOT PROCESSED\n", raw_token);
                i += 1; 
                break;
        }
    }
}





void decode_binxml(uint8_t *chunk_buffer,        /* the 64KB chunk in memory */
                   uint32_t binxml_offset,       /* start position of binxml, related to chunk_buffer */
                   uint32_t binxml_size,         /* the size of buffer =  record_size - 24 - 4  */       
                   uint32_t output_mode,         /* CSV or DEBUG etc */
                   XML_TREE *xtree)              /* XML TREE of output */
{
    // binxml can be splitted into 3 parts:
    //     {template-ID-Offset} {optional: definition} {instance data}
    //     part1: leading 0f token and 0C token, specify template ID and offset 
    //     part2: (optional) the definition of template, but it maybe located in other records
    //     part3: instance data array, we call this as value_table, will be substituted for %# of 0E token
    // decode the binxml by following steps
    //     1) find the tempalate offset from part1, get the offset of template_binxml
    //     2) find the starting position of part3, create value_table
    //     3) create the instance by mergring template with values


    uint32_t template_binxml_offset = 0x00;
    uint32_t template_binxml_size = 0x00;
    uint32_t value_table_offset = 0x00;

    EVTX_VALUE_TABLE value_table;

    if (CHECK_OUTMODE(output_mode, OUT_DEBUG)) {
        printf("decode_binxml() offset=0x%08" PRIx32 "\tsize=%" PRIu32 "\n", binxml_offset, binxml_size);
    }

    // first find template specified by token 0C, usuaaly in the very begining
    for (uint32_t i = binxml_offset; i < binxml_offset + 10; i++) { 
        if ((chunk_buffer[i] == 0x0c) && (chunk_buffer[i + 1] == 0x01)) {// found it.
            BINXML_TEMPLATE_INSTANCE_HEADER token_h;
            memcpy(&token_h, &chunk_buffer[i + 1], sizeof(token_h));

            EVTX_TEMPLATE_DEFINITION_HEADER th;
            memcpy(&th, &chunk_buffer[token_h.template_offset], sizeof(th));
                  // if needed, make sure this is a real template offset by checking 
                  //    if token_h.template_offset existing in index table (0x180 to 0x1ff)

            template_binxml_offset = token_h.template_offset + sizeof(th);
            template_binxml_size = th.data_size;
            value_table_offset = i + 1 + sizeof(token_h); // 1 byte is the token 0C itself

            //printf("DEBUG: found 0C 01 at 0x%08" PRIx32 "", i);
            //printf("\ttemplate_id=0x%08" PRIx32 "\tbinxml_offset=0x%08" PRIx32 "\tsize=%" PRIu32 "B\n", 
            //         th.template_id, template_binxml_offset, template_binxml_size);
            break; // no more need to loop since already found it.
         }
      }
      if (!template_binxml_offset) {
          printf("ERROR: no 0C token found\n"); // should never happen
          return;
      }

      // adjust the value_table_offset if part2 existing
      if ((binxml_offset < template_binxml_offset) && 
                 (template_binxml_offset < binxml_offset + binxml_size)) {
           // template binxml is within the original binxml, i.e. size of part2
           value_table_offset += template_binxml_size + sizeof(EVTX_TEMPLATE_DEFINITION_HEADER);
      }

      // build the value_table
      create_value_table(&value_table, chunk_buffer, value_table_offset, output_mode);

      // now, merge the template_binxml with value data
      decode_template_with_values(chunk_buffer, 
              template_binxml_offset, template_binxml_size, 
              &value_table, output_mode, xtree);

      // free memory
      delete_value_table(&value_table);
}







