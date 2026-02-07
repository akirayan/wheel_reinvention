
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "evtx_chunk.h"
#include "evtx_record.h"
#include "evtx_binxml.h"

#include "utf16le.h"
#include "timestamp.h"
#include "hex_dump.h"



typedef enum {
    BINXML_TOKEN_EOF                = 0x00,
    BINXML_TOKEN_OPEN_ELEMENT       = 0x01, // Also 0x41
    BINXML_TOKEN_CLOSE_START_TAG    = 0x02,
    BINXML_TOKEN_CLOSE_EMPTY_TAG    = 0x03,
    BINXML_TOKEN_END_ELEMENT        = 0x04,
    BINXML_TOKEN_VALUE              = 0x05, // Also 0x45
    BINXML_TOKEN_ATTRIBUTE          = 0x06, // Also 0x46
    BINXML_TOKEN_CDATA              = 0x07,
    BINXML_TOKEN_CHAR_REF           = 0x08,
    BINXML_TOKEN_ENTITY_REF         = 0x09,
    BINXML_TOKEN_PI_TARGET          = 0x0a,
    BINXML_TOKEN_PI_DATA            = 0x0b,
    BINXML_TOKEN_TEMPLATE_INSTANCE  = 0x0c,
    BINXML_TOKEN_SUBSTITUTION       = 0x0d,
    BINXML_TOKEN_OPT_SUBSTITUTION   = 0x0e,
    BINXML_TOKEN_FRAGMENT_HEADER    = 0x0f
} BINXML_TOKEN;




#pragma pack(push, 1)

// Token 0x01 / 0x41: Open Element
typedef struct {
    uint16_t dependency_id; // Usually 0xFFFF
    uint32_t element_size;   // Total size of this element branch
    uint32_t name_offset;    // Offset to Name Descriptor
} BINXML_OPEN_ELEMENT_HEADER;

// Token 0x05: Value Token
// This is followed by the actual data based on the type
typedef struct {
    uint8_t value_type;      // e.g., 0x01 for String, 0x04 for Hex32, etc.
} BINXML_VALUE_HEADER;

// Token 0x06 / 0x46: Attribute
typedef struct {
    uint32_t name_offset;    // Offset to Attribute Name
} BINXML_ATTRIBUTE_HEADER;

// Token 0x0C: Template Instance Header
// the 33-byte structure including 24-byte of TEMPLATE_DEFINITION_HEADER
// now I use the 9-byte structure only
typedef struct {
    uint8_t  unknown_val;         // unknown but usually seen as 0x01
    uint32_t template_id;      // the template ID as same as template_id
    uint32_t template_offset;   // offset to TEMPLATE_DEFINITION_HEADER, usually next 4 bytes
} BINXML_TEMPLATE_INSTANCE_HEADER;

#pragma pack(pop)








// --- Corrected Utility function to format and print a GUID ---
static void print_guid(const uint8_t *guid) {
    // GUID structure: 
    // Data1 (4 bytes - LE), Data2 (2 bytes - LE), Data3 (2 bytes - LE), 
    // Data4 (2 bytes - BE), Data5 (6 bytes - BE)
    
    printf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
           guid[3], guid[2], guid[1], guid[0],   // Data1: 4 bytes LE
           guid[5], guid[4],                     // Data2: 2 bytes LE
           guid[7], guid[6],                     // Data3: 2 bytes LE
           guid[8], guid[9],                     // Data4: 2 bytes BE (No swap)
           guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]); // Data5: 6 bytes BE
}


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
 * 同時にキャッシュリストへの登録も行う。
 *
 * @param buffer  BinXMLのバッファ
 * @param pos     現在の読み込み位置（NameOffsetの直後の位置）
 * @param name_off 解析したNameOffset
 * @return スキップすべきバイト数（実体がない場合は0）
 */
static int get_inline_name_skip_bytes(const uint8_t *buffer, uint32_t pos, uint32_t name_off) 
{
    // すでにキャッシュされている＝実体はこの場所にはない
    if (chunk_name_offset_is_cached(name_off)) {
        return 0;
    }

    // まだ登録されていない場合、ここに実体（Header + UTF-16 String）がある
    EVTX_NAME_ENTRY_HEADER nh;
    memcpy(&nh, &buffer[pos], sizeof(nh));

    // 実体のサイズ = ヘッダー(8) + 文字列(文字数 * 2)
    uint32_t skip_size = sizeof(nh) + (nh.char_count * 2);

    // 次回からはスキップ（0を返す）するようにキャッシュへ登録
    chunk_name_offset_add_cache(name_off);

    return (int)skip_size;
}





// Simple Indentation Helper
static void print_indent(int depth) {
    for (int i = 0; i < depth; i++) printf("  ");
}


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

void get_value_by_index(EVTX_VALUE_TABLE *tbl, uint8_t *chunk_buffer, uint32_t index);


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
static void create_value_table(EVTX_VALUE_TABLE *tbl, uint8_t *chunk_buffer, uint32_t value_table_offset)
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

    // DEBUG output
    for (uint32_t i = 0; i < count; i++) {
        printf("%%%" PRIu32 "\t", i);
        get_value_by_index(tbl, chunk_buffer, i);
        printf("\n");
    }
}

// free the allocated memory
static void delete_value_table(EVTX_VALUE_TABLE *tbl)
{
    free(tbl->items);
}

// get the value by index
void get_value_by_index(EVTX_VALUE_TABLE *tbl, uint8_t *chunk_buffer, uint32_t index)
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
            //printf("\n");
            //hex_dump_bytes(chunk_buffer + val_item->value_offset, val_item->size);

            //printf("\nDEBUG: called from get_value_by_index()\t");
            // decode it
            printf("\n");
            decode_binxml(chunk_buffer, val_item->value_offset, val_item->size); 

            // parse_binxml_stream(&sub_ctx);
            break;
       }

       default:
           printf("[Unknown Type 0x%02x, size %d]", type, size);
           break;
    }
}










void decode_binxml(uint8_t *chunk_buffer,        /* the 64KB chunk in memory */
                   uint32_t binxml_offset,       /* start position of binxml, related to chunk_buffer */
                   uint32_t binxml_size)         /* the size of buffer =  record_size - 24 - 4  */       
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

    printf("DEBUG: decode_binxml() offset=0x%08" PRIx32 "\tsize=%" PRIu32 "\n", binxml_offset, binxml_size);

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
      if ((binxml_offset < template_binxml_offset) && (template_binxml_offset < binxml_offset + binxml_size)) {
           // template binxml is within the original binxml, i.e. size of part2
           value_table_offset += template_binxml_size + sizeof(EVTX_TEMPLATE_DEFINITION_HEADER);
      }

      // build the value_table
      create_value_table(&value_table, chunk_buffer, value_table_offset);


      // now, merge the template_binxml with value data




      // free memory
      delete_value_table(&value_table);
}



void OLD_decode_binxml(uint8_t *chunk_buffer, /* the 64KB chunk in memory */
                   uint8_t *buffer,       /* buffer holding whole binxml                 */       
                   uint32_t size)         /* the size of buffer =  record_size - 24 - 4  */       
{
    int i = 0;  // the cursor in buffer
    int is_parsing_template = -1;
    int template_end_pos = 0;
    int depth = 0;

    while (i < size) {
        uint8_t raw_token = buffer[i];
        int has_more_data = ((raw_token & 0x40) != 0);
        uint8_t token = raw_token & 0x3F; // Strip the 0x40 flag for the switch
        
        switch (token) {

            case 0x00: // BinXmlTokenEOF
                //printf("</Fragment>\n");
                if (is_parsing_template && i + 1 == template_end_pos) {
                    printf("--- Template Definition End ---\n");
                    is_parsing_template = 0;
                    template_end_pos = 0;
                }
                i += 1;
                break;

            case BINXML_TOKEN_FRAGMENT_HEADER: //0x0F
            {
                // printf("DEBUG token=%02X (0x%08x)\n", raw_token, i);
                // Structure: [Token 1B] [MajorVersion 1B] [MinorVersion 1B] [Flags 1B]
 
                i += 4; 
                break;
            }

            case BINXML_TOKEN_TEMPLATE_INSTANCE: // 0x0C
            {
                BINXML_TEMPLATE_INSTANCE_HEADER th0C;
                // トークン 0x0C の直後(i+1)から9バイト分を構造体にコピー
                memcpy(&th0C, &buffer[i + 1], sizeof(th0C));
            
                // move i to current position
                i += 1 + sizeof(th0C); // ヘッダー分を進めて内部のパースへ
 
                // now there is a TEMPLATE_DEFINITION
                //typedef struct _EVTX_TEMPLATE_DEFINITION_HEADER {
                //    uint32_t next_offset;          // 0x00: link to next entry if needed 
                //    uint32_t template_id;          // 0x04: Template ID
                //    uint8_t  unknown_guid[12];     // 0x08: 12 bytes unknown or guid-like
                //    uint32_t data_size;            // 0x14: size of following binxml data
                //} EVTX_TEMPLATE_DEFINITION_HEADER;
                //

                EVTX_TEMPLATE_DEFINITION_HEADER th;
                memcpy(&th, chunk_buffer + th0C.template_offset, sizeof(th));

                uint32_t binxml_offset = th0C.template_offset + sizeof(th);
                uint32_t binxml_size =  th.data_size;
                decode_binxml(chunk_buffer, binxml_offset, binxml_size);

                // need to check if this is inline definition


             ////TO-DO-HERE

                // テンプレートデータの開始位置：Token(1) + Header(33)
                uint32_t data_start = i + 34; 
                // 終了位置を保存（この位置に 0x00 トークンが来るはず）
                template_end_pos = data_start + th.data_size;
                is_parsing_template = 1;
            
                printf("--- Template Definition Start (ID: 0x%08x, templ.data_size=0x%x) ---\n", 
                        th0C.template_id,  th.data_size);
            
                i += 34; // ヘッダー分を進めて内部のパースへ
                break;
            }
            
            case 0x0E: // BinXmlTokenOptionalSubstitution
            {
                //printf("token=0x0E BinXmlTokenOptionalSubstitution\n");
            
                i += 1; // token
                uint16_t sub_id = *(uint16_t*)&buffer[i];
                i += 2; // ID
                uint8_t v_type = buffer[i];
                i += 1; // Type
            
                printf("        %%%u (%s)\n", 
                        sub_id, get_value_type_name(v_type));
                break;
            }
            
            
            case 0x01: // BinXmlTokenOpenStartElement
            case 0x41: // BinXmlTokenOpenStartElement | BinXmlTokenMoreData
            {
                i += 1; // consume token
            
                BINXML_OPEN_ELEMENT_HEADER open_el;
                memcpy(&open_el, &buffer[i], sizeof(open_el));
            
                print_indent(depth++);
                printf("<");
                print_name_from_offset_buffer(chunk_buffer, open_el.name_offset);
            
                // ヘッダー分（DependencyID + DataSize + NameOffset）進める
                i += sizeof(open_el);
            
                // 名前の実体（Inline Name）があればスキップ
                i += get_inline_name_skip_bytes(buffer, i, open_el.name_offset);
                
            
                // もし 0x41 (MoreData) なら、名前の直後に続く
                // 「属性リストのサイズ情報 (4バイト)」を消費してスキップする
                if (raw_token & 0x40) { 
                    // この 4バイトは属性リスト全体の長さを示す
                    // uint32_t attr_list_size = *(uint32_t*)&buffer[i]; 
                    i += 4; 
                }
            
                break;
            }
            
            
            case 0x06: // BinXmlTokenAttribute
            case 0x46: // BinXmlTokenAttribute | BinXmlTokenMoreData
            {
                i += 1;
            
                BINXML_ATTRIBUTE_HEADER attr;
                memcpy(&attr, &buffer[i], sizeof(attr));
            
                printf(" ");
                print_name_from_offset_buffer(chunk_buffer, attr.name_offset);
                printf("=");
            
                i += sizeof(attr);
            
                // インライン名のスキップ
                i += get_inline_name_skip_bytes(buffer, i, attr.name_offset);
            
                // 0x46 の場合は、属性値（0x05など）の前に 4バイトのサイズ情報がある場合がある
                // ※仕様上、0x46のMoreDataフラグは直後のデータの解釈に影響します
            //    if (raw_token & 0x40) {
            //        i += 4;
            //    }
            
                break;
            }
            
            case 0x05: // BinXmlTokenValue
            {
                i += 1; // consume token (0x05)
                uint8_t v_type = buffer[i]; 
                i += 1; // consume type
            
                printf(" (Type:0x%02x) Value: ", v_type);
            
                switch (v_type) {
                    case 0x01: // Unicode String
                    {
                        uint16_t char_count = *(uint16_t*)&buffer[i];
                        i += 2;
                        // 前回の UTF-16LE 表示ロジック
                        print_utf16le_string(char_count, (uint16_t *)&buffer[i]);
                        printf("\n");
                        i += (char_count * 2);
                        break;
                    }
                    case 0x14: // SID (Binary Form)
                    {
                        // SIDの長さは 8 + (SubAuthorityCount * 4)
                        // buffer[i+1] が SubAuthorityCount
                        uint8_t count = buffer[i + 1];
                        uint32_t sid_size = 8 + (count * 4);
                        printf("[SID: Size %d]", sid_size);
                        printf("\n");
                        i += sid_size;
                        break;
                    }
                    case 0x04: // UInt16
                        printf("%u", *(uint16_t*)&buffer[i]);
                        printf("\n");
                        i += 2;
                        break;
                    case 0x08: // UInt32
                        printf("%u", *(uint32_t*)&buffer[i]);
                        printf("\n");
                        i += 4;
                        break;
                    default:
                        printf("[Pointer/Other Type skip]");
                        printf("\n");
                        // テンプレート定義内では、不明な型は慎重に扱う必要があります
                        break;
                }
                break;
            }
            
            
            case BINXML_TOKEN_CLOSE_START_TAG: // 0x02
                printf(">\n");
                i += 1;
                break;

            case BINXML_TOKEN_END_ELEMENT: // 0x04
                depth--;
                print_indent(depth);
                printf("</>\n"); // Or track element names in a stack to print </Event>
                i += 1;
                break;

            case BINXML_TOKEN_CLOSE_EMPTY_TAG: // 0x03
                printf(" />\n");
                i += 1;
                break;


            default:
                i += 1; 
                break;
        }


        if (is_parsing_template == 0) 
            break; // break from loop
    }

    

    // 2. ループを抜けた直後（i == template_end_pos のはず）
    if (is_parsing_template == 0) {
        printf("\n--- Value Table Analysis ---\n");
        
    }
}




// token 0x01
void handle_start_element(BinXmlContext *ctx) {
    // Current data_ptr is at offset 0x01 of the token
    
    // 1. Skip Tag Dependency (2B) and Size (4B)
    ctx->data_ptr += 6; 
    
    // 2. Read Name Offset (4B)
    uint32_t name_offset = *(uint32_t *)ctx->data_ptr;
    ctx->data_ptr += 4;
    
    // 3. Read Attribute Flag (1B)
    uint8_t has_attributes = *ctx->data_ptr;
    ctx->data_ptr += 1;

    // 4. Resolve Name using your chunk_buffer
    // Format: [2B char_count] [UTF-16 chars...] [2B null]
    uint16_t *name_ptr = (uint16_t *)(ctx->chunk_buffer + name_offset);
    uint16_t char_count = *name_ptr;
    uint16_t *utf16_name = name_ptr + 1; // Move past the 2B count

    printf("<");
    print_utf16le_string(char_count, utf16_name);

    // If no attributes follow, we can close the start tag bracket here.
    // If attributes DO follow, the loop in parse_binxml_stream 
    // will pick up the 0x02 (Attribute) tokens next.
    if (!has_attributes) {
        printf(">");
    }
}

// token 0x41

void handle_text_value(BinXmlContext *ctx) {
    // data_ptr is currently at offset 0x01 (Dependency)
    
    // 1. Skip Dependency (2B), Data Size (4B), Name Offset (4B), 
    //    Next Offset (4B), and Hash (2B) = 16 bytes total
    ctx->data_ptr += 16;

    // 2. Read the 2-byte Char Count
    uint16_t char_count = *(uint16_t *)ctx->data_ptr;
    ctx->data_ptr += 2;

    // 3. Extract and print the UTF-16LE string
    uint16_t *utf16_data = (uint16_t *)ctx->data_ptr;
    
    // Use your iconv helper
    print_utf16le_string(char_count, utf16_data);

    // 4. Advance the pointer: (char_count * 2) bytes + 2 bytes for Null
    ctx->data_ptr += (char_count * 2) + 2;

    // Safety: ensure we don't exceed end_ptr
    if (ctx->data_ptr > ctx->end_ptr) {
        ctx->data_ptr = ctx->end_ptr;
    }
}




// 0x0C


void handle_template_definition(BinXmlContext *ctx) {
    // Current ctx->data_ptr is at offset 0x01 of the 0x0C structure
    
    // 1. Safety check: Do we have enough bytes left for the 0x0C header (9 bytes)?
    if (ctx->data_ptr + 9 > ctx->end_ptr) {
        return;
    }

    uint8_t flag = *ctx->data_ptr++; 

    // 2. Read Template ID (4B) - Use memcpy for alignment safety
    uint32_t template_id;
    memcpy(&template_id, ctx->data_ptr, 4);
    ctx->data_ptr += 4;

    // 3. Read Template Definition Offset (4B)
    uint32_t template_def_offset;
    memcpy(&template_def_offset, ctx->data_ptr, 4);
    ctx->data_ptr += 4;

    // Save the resume point in the current record's stream
    uint8_t *resume_ptr = ctx->data_ptr;

    // 4. Calculate the absolute address of the Template (0x0E)
    // template_def_offset is relative to the start of the Chunk
    uint8_t *template_base = ctx->chunk_buffer + template_def_offset;

    // 5. VALIDATION: Prevent Bus Error by checking bounds and token signature
    // Assuming a standard Chunk size of 64KB (0x10000)
    if (template_def_offset > 0x10000) {
        fprintf(stderr, "[Error] Template offset 0x%X is out of chunk bounds\n", template_def_offset);
        return;
    }

    if (*template_base != 0x0E) {
        // If we don't find 0x0E, the offset logic is wrong. 
        // We shouldn't crash; we should just return and skip the template.
        return;
    }

    // 6. Map the 24-byte Template Definition Header
    EVTX_TEMPLATE_DEFINITION_HEADER th;
    memcpy(&th, template_base + 1, sizeof(EVTX_TEMPLATE_DEFINITION_HEADER));
    
    // 7. Initialize sub-context for RECURSION
    // The BinXML data starts immediately after the 24-byte header
    BinXmlContext template_ctx;
    template_ctx.chunk_buffer = ctx->chunk_buffer;
    template_ctx.data_ptr = template_base + 1 + sizeof(EVTX_TEMPLATE_DEFINITION_HEADER);
    template_ctx.end_ptr = template_ctx.data_ptr + th.data_size;

    // Double check: Ensure the sub-context doesn't exceed the chunk memory
    if (template_ctx.end_ptr > ctx->chunk_buffer + 0x10000) {
        template_ctx.end_ptr = ctx->chunk_buffer + 0x10000;
    }

    // 8. RECURSE: Parse the template structure
    // This uses the shared value table to resolve 0x0D substitutions
    parse_binxml_stream(&template_ctx);

    // 9. Return the main pointer to the point right after the 0x0C block
    ctx->data_ptr = resume_ptr;
}



void parse_binxml_stream(BinXmlContext *ctx) {
    // Continue only as long as we are within the allocated size
    while (ctx->data_ptr < ctx->end_ptr) {
        uint8_t token = *ctx->data_ptr++;

        switch (token) {
            case 0x0C: // Template Definition
                handle_template_definition(ctx);
                break;

            case 0x01: // Start Element
                handle_start_element(ctx);
                break;

            case 0x05: // End Element (</tag>)
                printf("</tag_name_placeholder>"); 
                break;

            case 0x0D: // Substitution
            {
                if (ctx->data_ptr + 2 > ctx->end_ptr) break; // Safety check
                uint16_t index = *(uint16_t *)ctx->data_ptr;
                ctx->data_ptr += 2;
                get_item_value_by_index(ctx->chunk_buffer, index);
                break;
            }

            case 0x41: // Normal Text Value
                handle_text_value(ctx);
                break;

            case 0x00: // End of Token Stream
                break;
                //return;
        }
    }
}
