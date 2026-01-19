/* evtx_schema.c
 *
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>




#define EVTX_FILE_HEADER_BLOCK_SIZE 0x1000
#define EVTX_CHUNK_SIZE             0x10000
#define BYTES_PER_LINE              16

#pragma pack(push, 1)
typedef struct _EVTX_FILE_HEADER {
    uint8_t  signature[8];       // 0x00  "ElfFile\x00"
    uint64_t first_chunk_number; // 0x08  
    uint64_t last_chunk_number;  // 0x10
    uint64_t next_record_id;     // 0x18
    uint32_t header_size;        // 0x20 (128)
    uint16_t minor_version;      // 0x24 (2)
    uint16_t major_version;      // 0x26 (3)
    uint16_t header_block_size;  // 0x28 (4096) or call this as chunk_data_offset
    uint16_t chunk_count;        // 0x2A 
    uint8_t  unused[76];         // 0x2C 
    uint32_t flags;              // 0x78  (0x01: Dirty, 0x02: Full)
    uint32_t checksum;           // 0x7C  signatureからflagsまでの120バイトのCRC32
    uint8_t  padding[3968];      // 0x80
} EVTX_FILE_HEADER;
#pragma pack(pop)


#pragma pack(push, 1)
typedef struct _EVTX_CHUNK_HEADER {
    uint8_t  signature[8];          // 0x00: "ElfChnk\x00"
    uint64_t first_record_number;   // 0x08: First Event Record Number
    uint64_t last_record_number;    // 0x10: Last Event Record Number
    uint64_t first_record_identifier; // 0x18: First Event Record ID
    uint64_t last_record_identifier;  // 0x20: Last Event Record ID
    uint32_t header_size;           // 0x28: 128 (0x80)
    uint32_t last_record_offset;     // 0x2C: 最後のレコードのChunk内相対位置
    uint32_t free_space_offset;     // 0x30: 空き領域のChunk内相対位置
    uint32_t data_checksum;         // 0x34: イベントデータ部分のCRC32
    uint8_t  unknown[64];           // 0x38 から64 bytes unkwown empty values 
    uint32_t unknown_flags;         // mot sure
    uint32_t checksum;              // checksum of first 120 bytes
    uint32_t string_offset_array[64]; // common string table offset, 64 x 4bytes = 256 bytes
    uint32_t template_ptr_array[32]; // template table pointer array, 32 x 4bytes = 128 bytes
} EVTX_CHUNK_HEADER;
#pragma pack(pop)



#pragma pack(push, 1)
// 文字列エントリの固定ヘッダー部分
typedef struct _EVTX_NAME_ENTRY_HEADER {
    uint32_t next_offset; // ハッシュ衝突時の次要素へのオフセット
    uint16_t hash;        // 文字列のハッシュ値
    uint16_t char_count;  // 文字列の長さ（文字数）
    // この後に UTF-16LE の文字列が続く (NULL終端ではない場合がある)
} EVTX_NAME_ENTRY_HEADER;
#pragma pack(pop)



#pragma pack(push, 1)
typedef struct _EVTX_TEMPLATE_DEFINITION_HEADER {
    uint32_t next_offset;          // 0x00: 次のテンプレートへのオフセット（衝突用）
    uint32_t template_id;          // 0x04: テンプレートID 
    uint8_t  guid[12];             // 0x08: 12バイト分 GUID
    uint32_t data_size;            // 0x14: 続くBinXMLデータのバイトサイズ
} EVTX_TEMPLATE_DEFINITION_HEADER;
#pragma pack(pop)



#pragma pack(push, 1)
typedef struct g16_EVTX_TEMPLATE_DEFINITION_HEADER {
    uint32_t next_offset;    // 0x00: Offset to next template
    uint32_t template_id;    // 0x04: Template ID
    uint8_t  guid[16];       // 0x08: 16-byte GUID
    uint32_t data_size;      // 0x18: Size of following BinXML
} g16EVTX_TEMPLATE_DEFINITION_HEADER;
#pragma pack(pop)








#pragma pack(push, 1)
typedef struct _EVTX_EVENT_RECORD_HEADER {
    uint32_t signature;            // "\x2a\x2a\x00\x00" (unsigned int 0x00002a2a)
    uint32_t size;                 // レコード全体のサイズ
    uint64_t event_record_id;
    uint64_t timestamp;            // FILETIME format
} EVTX_EVENT_RECORD_HEADER;
#pragma pack(pop)


// イメージ：レコード側にある値の配列
typedef struct _EVTX_SUBSTITUTION_ARRAY {
    uint16_t ValueCount;
    struct {
        uint16_t Size;
        uint8_t  Type;  // 0x01: Unicode String, 0x04: UInt32 など
    } Values[1]; // 実際には ValueCount 分続く
} EVTX_SUBSTITUTION_ARRAY;






// オフセットから名前（Name Entry）を解析して表示する関数
void print_name_from_offset(FILE *fp, long chunk_base, uint32_t name_offset) {
    if (name_offset == 0) return;

    // 現在のファイル位置を保存（呼び出し元に戻れるようにするため）
    long saved_pos = ftell(fp);

    // 文字列エントリ（Name Entry）の場所へジャンプ
    fseek(fp, chunk_base + name_offset, SEEK_SET);

    EVTX_NAME_ENTRY_HEADER n_header;
    // for reference, the struct defined as
    //    uint32_t next_offset; // ハッシュ衝突時の次要素へのオフセット
    //    uint16_t hash;        // 文字列のハッシュ値
    //    uint16_t char_count;  // 文字列の長さ（文字数）
    //    // この後に UTF-16LE の文字列が続く (NULL終端ではない場合がある)
    if (fread(&n_header, sizeof(n_header), 1, fp) != 1) {
        fseek(fp, saved_pos, SEEK_SET);
        return;
    }

    // UTF-16文字列を読み込む（文字数 * 2バイト）
    // 安全のため最大長をチェックしたり、mallocの失敗を考慮してください
    uint16_t *utf16_str = malloc(n_header.char_count * 2 + 2);
    if (utf16_str) {
        fread(utf16_str, 2, n_header.char_count, fp);
        
        //printf("      Found Name [Offset:0x%04" PRIx32 "]: Len=%d ", name_offset, n_header.char_count);
        printf("  [0x%04" PRIx32 "] ", name_offset);
        for (int j = 0; j < n_header.char_count; j++) {
            // 簡易的にASCII範囲のみ表示（英数字ならこれでOK）
            printf("%c", (char)utf16_str[j]);
        }
        printf("\n");
        free(utf16_str);
    }

    // ファイル位置を元に戻す
    fseek(fp, saved_pos, SEEK_SET);
}



static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s [-csv] file.evtx [EventID]\n", prog);
}

static void print_signature(uint8_t sig[8])
{
    int empty = 1;
    for (int i = 0; i < 8; i++) {
        if (sig[i] != '\0') {
            empty = 0;
            break;
        }
    }

    if (empty) {
        printf("        ");  // 8 spaces
    } else {
        printf("%.8s", sig);
    }
}



void print_evtx_file_header(EVTX_FILE_HEADER *fh, int csv_mode)
{
    // nothing to do on CSV mode
    if (csv_mode) return;

    // print the contents of head
    printf("== EVTX FILE HEADER ==\n");
    printf("Signature      : %.8s\n", fh->signature);
    printf("First_Chunk    : %" PRIu64 "\n", fh->first_chunk_number);
    printf("Last_Chunk     : %" PRIu64 "\n", fh->last_chunk_number);
    printf("Next_Record_ID : %" PRIu64 "\n", fh->next_record_id);
    printf("Header_Size    : %" PRIu32 "\n", fh->header_size);
    printf("Version        : %u.%u\n", fh->major_version, fh->minor_version);
    printf("Chunk_Offset   : 0x%" PRIx16 "\n", fh->header_block_size);
    printf("Chunk_Counts   : %" PRIu16 "\n", fh->chunk_count);
    printf("Flags          : 0x%02" PRIx32 "\n", fh->flags);
    printf("Checksum       : 0x%" PRIx32 "\n", fh->checksum);
}






void decode_common_string_entry(FILE *fp, long chunk_base, uint32_t offset, int entry_index) {

    // 1. jump to the offset position 
    //        --- not in first 512 bytes, but any other location with the chunk
    //    chunk_base is the start point (bytes) of this chunk, 
    //        it was calculated as: 4096 (evtx file block size) + 65636 (64KB) * chunk_index
    //    offsets is bytes related to chunk_base for this NAME ENTRY
    //    so the real location of this NAME ENTRY is at: chunk_base + offset
    fseek(fp, chunk_base + offset, SEEK_SET);
    
    // 2. read the NAME ENTRY HEADER (fix size part)
    EVTX_NAME_ENTRY_HEADER n_header;
    fread(&n_header, sizeof(n_header), 1, fp);
    // for reference, the struct defined as
    //    uint32_t next_offset; // ハッシュ衝突時の次要素へのオフセット
    //    uint16_t hash;        // 文字列のハッシュ値
    //    uint16_t char_count;  // 文字列の長さ（文字数）
    //    // UTF-16LE text continues after this point

    // 3. read the UTF-16LE string, maybe not terminated by NULL
    uint16_t *utf16_str = malloc(n_header.char_count * 2 + 2); 
       // 2 bytes for one UTF-16LE char, and plus 2 bytes to hold NULL
    fread(utf16_str, 2, n_header.char_count, fp);
    utf16_str[n_header.char_count] = 0; // make sure it's termibated by NULL

    // 4. show summary line
    printf("  [%02d] Offset:0x%04x Next_offset:0x%04x Hash:0x%04x Len:%d Value: ", 
           entry_index, offset, n_header.next_offset, n_header.hash, n_header.char_count);
    
    // 5. show the UTF-16LE char-by-char, if Japanese character, maybe trouble
    for(int j = 0; j < n_header.char_count; j++) {
        printf("%c", (char)utf16_str[j]); 
    }
    printf("\n");

    // 6. free the memory space
    free(utf16_str);

    // 7. if n_header.next_offset is not 0, need to jump to next_offset
    if (n_header.next_offset > 0) { 
        // call ourself
        // using -1 to indicate it's a "next_offset"
        decode_common_string_entry(fp, chunk_base, n_header.next_offset, -1); 
    }
}



void decode_common_string_offset_array(FILE *fp, long chunk_base) {

    // these 64 uint32_t holds the offset bytes of EVTX_NAME_ENTRY_HEADER
    // called "common string offset array", not EVTX_NAME_ENTRY_HEADER itself
    uint32_t string_offsets[64];  
    
    // 1. The "common string offset array" localted at 0x80 (128B) -- hard-coded
    fseek(fp, chunk_base + 128, SEEK_SET);
    fread(string_offsets, sizeof(uint32_t), 64, fp);

    printf("  --- Common String Table ---\n");

    // process each uint32 entry
    for (int i = 0; i < 64; i++) {
        // if the uint32 is 0x0 0x0 0x0 0x0, then this entry is not used yet, skip it
        if (string_offsets[i] == 0) continue;

        // call function to process each
        decode_common_string_entry(fp, chunk_base, string_offsets[i], i);
    }
}





#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

void dump_hex(FILE *fp, long chunk_base, uint32_t relative_offset, uint32_t size) 
{
    // just dump the bytes as HEX

    if (size == 0) {
        printf("    [dump_hex] size = 0, nothing to dump\n");
        return;
    }

    long pos = chunk_base + relative_offset;
    if (fseek(fp, pos, SEEK_SET) != 0) {
        perror("fseek(dump_hex)");
        return;
    }

    uint8_t buf[BYTES_PER_LINE];
    uint32_t remaining = size;
    uint32_t offset = 0;

    while (remaining > 0) {
        uint32_t to_read =
            remaining > BYTES_PER_LINE ? BYTES_PER_LINE : remaining;

        size_t n = fread(buf, 1, to_read, fp);
        if (n == 0) {
            printf("    [dump_hex] fread failed or EOF\n");
            break;
        }

        /* hex dump */
        printf("%08x  ", offset);
        for (size_t i = 0; i < BYTES_PER_LINE; i++) {
            if (i < n) {
                printf("%02x ", buf[i]);
            } else {
                printf("   ");
            }
            if (i == 7) printf(" "); // add a space
        }

        /* ASCII dump */
        printf(" |");
        for (size_t i = 0; i < n; i++) {
            if (i < n)
                printf("%c", isprint(buf[i]) ? buf[i] : '.');
            else
                printf(" ");

            if (i == 7) printf(" "); // add a space
        }
        printf("|\n");

        remaining -= n;
        offset += n;
    }
}








// BinXML Tokens
#define TOK_EOF               0x00
#define TOK_ELEMENT_START     0x01
#define TOK_ATTRIBUTE         0x02
#define TOK_FRAGMENT_HEADER   0x0F
#define TOK_SUBSTITUTION      0x0D // 0x0D is very common in templates




// Helper to read and print UTF-16LE strings from the file
void print_utf16_string(FILE *fp, uint32_t *processed) {
    uint16_t wc;
    while (fread(&wc, 2, 1, fp) == 1 && wc != 0) {
        if (wc < 128) printf("%c", (char)wc);
        else printf("?"); 
        *processed += 2;
    }
    *processed += 2; // Account for the null terminator
}





void MY_decode_binxml(FILE *fp, long chunk_base, uint32_t binxml_offset, uint32_t binxml_size) {
    uint8_t *buffer = malloc(binxml_size);
    fseek(fp, chunk_base + binxml_offset, SEEK_SET);
    fread(buffer, 1, binxml_size, fp);

    printf("    --- BinXML Schema & Substitution Analysis ---\n");

    for (uint32_t i = 0; i < binxml_size; ) {
        uint8_t token = buffer[i];
        
        switch (token) {
            case 0x00: // Padding
                i++; 
                break;

            case 0x01: // OpenStartElementTag
            case 0x41: // ElementStart with more data
              //printf("DEBUG Token=0x%02x starting i=0x%04x\n", token, i);
            {
                // 1. DataSize と NameOffset を取得
                uint16_t dependency_identifier = *(uint16_t*)&buffer[i + 1]; // 0xff 0xff: not set
                uint32_t data_size = *(uint32_t*)&buffer[i + 3];
                uint32_t name_off  = *(uint32_t*)&buffer[i + 7];
                uint32_t next_off  = *(uint32_t*)&buffer[i + 11];
        
                // 2. 名前の定義部分（Hash + Len + String）を解析してスキップ
                // i + 15 が Hash(2バイト) の位置
                // i + 17 が char_count(2バイト) の位置
                uint16_t inline_len = *(uint16_t*)&buffer[i + 17]; // Len は i+13
              //printf("DEBUG Token=0x%02x inline_len=0x%04x\n", token, inline_len);
                
                // jump to Common_String_Entry to get the length and text
                printf("  [0x%04x] Token=0x%02x ", i, token);
                print_name_from_offset(fp, chunk_base, name_off & 0xFFFF);
                
                // 次のトークンへジャンプ: 
                // 1 (token) +  14 (Header) + 2 (Hash) + 2 (Len) + (Len * 2)
                i +=  1 + 14 + 2 + 2 + (inline_len * 2); 

                // skip 2 bytes NULL or padding
                i += 2;

                if (token == 0x41) { // has more data
                    uint32_t more_data_size = *(uint32_t*)&buffer[i];
                    i += 4;
                }
              //printf("DEBUG Token=0x%02x moved to i=0x%04x\n", token, i);
            }
              //printf("DEBUG Token=0x%02x finished i=0x%04x\n", token, i);
                break;


            case 0x02: // BinXmlTokenCloseStartElementTag
            case 0x03: // BinXmlTokenCloseEmptyElementTag
            case 0x04: // BinXmlTokenEndElementTag 
                 i++;
                 break;

           case 0x05: // BinXmlTokenAttribute
           case 0x45: 
           {
               // 現在の i はトークン 0x05 自体の位置
               // 直後の 1バイトが Value Type (0x01 = ValueText)
               uint8_t value_type = buffer[i + 1];
               
               if (value_type == 0x01) { 
                   // 0x01 の後に 2バイトの文字数 (char_count) が続く
                   uint16_t char_count = *(uint16_t*)&buffer[i + 2];
                   
                   printf("  [0x%04x] Token=0x%02x   ", i, token);
       
                   // UTF-16LE 文字列の読み込み
                   uint16_t *utf16_str = malloc(char_count * 2 + 2);
                   if (utf16_str) {
                       // すでにメモリ上にある buffer からコピーするのが最も効率的です
                       memcpy(utf16_str, &buffer[i + 4], char_count * 2);
                       utf16_str[char_count] = 0; // 終端
                       // simple print the ascii code 
                       for (int j = 0; j < char_count; j++) {
                           printf("%c", (char)utf16_str[j]);
                       }
                       printf("\n");
                       free(utf16_str);
                   }
       
                   // 次のトークンへ進む
                   // Token(1) + Type(1) + Count(2) + String(Count*2)
                   i += 4 + (char_count * 2);
               } else {
                   // ValueType が 0x01 以外（例：Substitution ID など）の場合
                   printf("  [0x%04x] Token=0x%02x   (value_type=0x%02x)\n", i, token, value_type);
                   i += 2; // 最低限 Token と Type 分進める
               }
               break;
          }


           case 0x06: // BinXmlTokenAttribute
           case 0x46: // BinXmlTokenAttribute
           {
                uint32_t name_off = *(uint32_t*)&buffer[i + 1];
                printf("  [0x%04x] Token=0x%02x ", i, token);
                print_name_from_offset(fp, chunk_base, name_off & 0xFFFF);
                i += 5; // Token(1) + Offset(4)
                break;
           }


            case 0x0C: // Template instance
                printf("  [0x%04x] Token=0x%02x \n", i, token);
                 i += 1;
                 // from this byte, start Template Definition
               {
                 uint8_t unknown1 = *(uint8_t*)&buffer[i];
                 uint32_t unknown4 = *(uint32_t*)&buffer[i + 1]; // maybe templete identifier
                 uint32_t template_def_offset = *(uint32_t*)&buffer[i + 5]; // 
                 uint32_t next_offset = *(uint32_t*)&buffer[i + 9]; // 
                 uint8_t  guid[16];
                       memcpy((uint8_t*)guid, &buffer[i + 13], 16);
                 uint32_t data_size = *(uint32_t*)&buffer[i + 29]; // 
                       // then is Fragment Header 0x0F
                       // and elements
                       // finaly BinXmlTokenEOF
                 // move to next token
                 i += 33;
               }
                 break;


            case 0x0D: // BinXmlTokenNormalSubstitution   Value Text (固定文字列など)
            case 0x0E: // Substitution (Optional)
                {
                    uint16_t  substitution_identifier = *(uint16_t*)&buffer[i + 1];
                    uint8_t  value_type = *(uint8_t*)&buffer[i + 3];
                    printf("  [0x%04x] Token=0x%02x   (subst_id=%d value_type=0x%02x)\n", 
                                          i, token, substitution_identifier, value_type);
                    i += 4;
                }
                break;

            case 0x0F: // BinXmlFragmentHeaderToken  Template Instance Header
                i += 4; 
                break;

            default:
                printf("  [0x%04x] Token=0x%02x   ***NOT DECODED***\n", i, token);
                i++;
                break;
        }
    }
    free(buffer);
}




#include <stdbool.h>

// Helper to determine if a byte at a specific position is a likely valid BinXML token
bool is_likely_token(uint8_t *buffer, uint32_t i, uint32_t size) {
    if (i >= size) return false;
    uint8_t t = buffer[i] & 0x3F; // Strip 0x40 flag
    // Common tokens in templates: 0x01-0x06, 0x0C-0x0F, and 0x00
    return (t >= 0x00 && t <= 0x11);
}

void decode_binxml(FILE *fp, long chunk_base, uint32_t binxml_offset, uint32_t binxml_size) {
    uint8_t *buffer = malloc(binxml_size);
    if (!buffer) return;
    
    fseek(fp, chunk_base + binxml_offset, SEEK_SET);
    fread(buffer, 1, binxml_size, fp);

    printf("    --- Improved BinXML Analysis ---\n");

    for (uint32_t i = 0; i < binxml_size; ) {
        uint8_t token = buffer[i];
        
        switch (token & 0x3F) { // Use mask to handle 0x4x variants
            case 0x00: // EOF or Padding
                i++; 
                break;

            case 0x01: // Element Start
            case 0x02: // Attribute (Standard)
            case 0x06: // Attribute (Template)
            {
                uint32_t name_off;
                bool expanded = false;

                // Peek Logic: Determine if header is 5 or 11 bytes
                if (token & 0x40) {
                    expanded = true;
                } else if (i + 5 < binxml_size) {
                    // If compact (5 bytes), is the next byte a valid token? 
                    // If not, it's likely an expanded header.
                    if (!is_likely_token(buffer, i + 5, binxml_size)) {
                        expanded = true;
                    }
                }

                if (expanded && (i + 10 < binxml_size)) {
                    // Expanded Header: Token(1) + Dep(2) + Size(4) + NameOff(4)
                    name_off = *(uint32_t*)&buffer[i + 7];
                    printf("  [0x%04x] Token=0x%02x (Exp) ", i, token);
                    print_name_from_offset(fp, chunk_base, name_off);
                    i += 11;
                } else {
                    // Compact Header: Token(1) + NameOff(4)
                    name_off = *(uint32_t*)&buffer[i + 1];
                    printf("  [0x%04x] Token=0x%02x (Cmp) ", i, token);
                    print_name_from_offset(fp, chunk_base, name_off);
                    i += 5;
                }
                printf("\n");
                break;
            }

            case 0x05: // Attribute Value
            {
                uint8_t value_type = buffer[i + 1];
                printf("  [0x%04x] Token=0x05 ", i);
                
                if (value_type == 0x01 && (i + 3 < binxml_size)) { // Literal String
                    uint16_t char_count = *(uint16_t*)&buffer[i + 2];
                    printf("Value: ");
                    for (int j = 0; j < char_count; j++) {
                        // Cast UTF-16LE to char for simple console output
                        printf("%c", (char)buffer[i + 4 + (j * 2)]);
                    }
                    printf("\n");
                    i += 4 + (char_count * 2);
                } else {
                    printf("(ValueType=0x%02x)\n", value_type);
                    i += 2;
                }
                break;
            }

            case 0x0D: // Substitution
            case 0x0E:
            {
                uint16_t sub_id = *(uint16_t*)&buffer[i + 1];
                uint8_t type = buffer[i + 3];
                printf("  [0x%04x] Token=0x%02x (SubstID=%d Type=0x%02x)\n", i, token, sub_id, type);
                i += 4;
                break;
            }

            case 0x04: // End Element
                printf("  [0x%04x] Token=0x04 </>\n", i);
                i++;
                break;

            case 0x0F: // Fragment Header
                i += 4; 
                break;

            default:
                // If we hit unknown, skip 1 and hope for realignment
                i++; 
                break;
        }
    }
    free(buffer);
}






void decode_template_ptr_entry(FILE *fp, long chunk_base, uint32_t offset, int entry_index) {

    // 1. read the TEMPLATE Definition Header (fixed size)
    //    chunk_base is the startpoint of this chunk, 
    //        it was calculated as: 4096 + 65536 * chunk_index
    //    offset is the bytes related to chunk_base
    fseek(fp, chunk_base + offset, SEEK_SET);
    EVTX_TEMPLATE_DEFINITION_HEADER t_header;
    fread(&t_header, sizeof(t_header), 1, fp);
    // for refence, here is the stuct
      // uint32_t next_offset;          // 0x00: 次のテンプレートへのオフセット（衝突用）
      // uint32_t template_id;          // 0x04: テンプレートID 
      // uint8_t  guid[12];             // 0x08: 12バイト分 GUID
      // uint32_t data_size;            // 0x14: 続くBinXMLデータのバイトサイズ

    // 2. print out summary
    uint32_t binxml_relative_offset = offset + sizeof(EVTX_TEMPLATE_DEFINITION_HEADER);
    uint32_t binxml_absolute_offset = chunk_base + binxml_relative_offset;
    printf("  [%02d] Offset:0x%04x Next_offset:0x%04x TemplateID:0x%08x BinXML_AbsOffset:%u Size:%u bytes\n", 
           entry_index, 
           offset, 
           t_header.next_offset, 
           t_header.template_id, 
           binxml_absolute_offset,
           t_header.data_size);

    // 3. BinXMLの解析へ進む
    // 構造体ヘッダーの直後から BinXML が始まります
    // call function for binxml
    dump_hex(fp, chunk_base, binxml_relative_offset, t_header.data_size);
    //decode_binxml(fp, chunk_base, binxml_relative_offset, t_header.data_size);

    // 4. if next_offset, recursive call ourself, but using -1 to indicate next_offset
    if (t_header.next_offset > 0) {
        // call ourself
        // using -1 to indicate it's a "next_offset"
        decode_template_ptr_entry(fp, chunk_base, t_header.next_offset, -1);
    }
}



void decode_template_ptr_array(FILE *fp, long chunk_base) {
    uint32_t template_offsets[32];
    
    // 1. TemplatePtr配列（384バイト目）へ移動して読み込む
    fseek(fp, chunk_base + 384, SEEK_SET);
    fread(template_offsets, sizeof(uint32_t), 32, fp);

    printf("  --- Template Table ---\n");

    // process each uint32 entry
    for (int i = 0; i < 32; i++) {
        // if the uint32 is 0x0 0x0 0x0 0x0, then this entry is not used yet, skip it
        if (template_offsets[i] == 0) continue;

        // call function to process each
        decode_template_ptr_entry(fp, chunk_base, template_offsets[i], i);
    }

}


void decode_evtx_chunk(FILE *fp, int chunk_index, int csv_mode)
{
    long chunk_base =
        EVTX_FILE_HEADER_BLOCK_SIZE + (long)chunk_index * EVTX_CHUNK_SIZE;

    // read the chunk header
    EVTX_CHUNK_HEADER ch; 
    fseek(fp, chunk_base, SEEK_SET);
    fread(&ch, sizeof(ch), 1, fp);

    // and print out header details
    printf("Chunk#%08" PRIu16 " ", chunk_index); 
    print_signature(ch.signature);

    printf(" size=%" PRIu32, ch.header_size);

    printf(" rec_num=%" PRIu64 "-%" PRIu64 ,
           ch.first_record_number,
           ch.last_record_number);

    printf(" rec_id=%" PRIu64 "-%" PRIu64 ,
           ch.first_record_identifier,
           ch.last_record_identifier);

    printf(" last_record_offset=0x%" PRIx32 " free_space_offset=0x%" PRIx32,
           ch.last_record_offset,
           ch.free_space_offset);

    printf(" checksum=0x%" PRIx32, ch.checksum);
    printf("\n");


    // decode common string array
    decode_common_string_offset_array(fp, chunk_base);

    // decode template definition table
    decode_template_ptr_array(fp, chunk_base);

}



int main(int argc, char **argv)
{
    const char *filename = NULL;
    int csv_mode = 0;
    int target_event_id = -1;

    /* ---- argument parse (最小) ---- */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-csv") == 0) {
            csv_mode = 1;
        } else if (!filename) {
            filename = argv[i];
        } else {
            target_event_id = atoi(argv[i]);
        }
    }

    if (!filename) {
        usage(argv[0]);
        return 1;
    }

    /* ---- ここから EVTX 読み取り開始 ---- */
    // printf("EVTX file: %s\n", filename);

    /* ---- file open ---- */
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }


    /* TODO:
     *  - read file header
     *  - enumerate chunks
     *  - walk records
     */

    EVTX_FILE_HEADER fh;
    //printf("DEBUG: size of EVTX_FILE_HEADER: %lu\n", sizeof(fh));

    // read file header
    fread(&fh, sizeof(fh), 1, fp);

    /* ---- verify the file signature ---- */
    if (memcmp(fh.signature, "ElfFile", 7) != 0) {
        fprintf(stderr, "ERROR: invalid EVTX signature: '%.8s'\n", fh.signature);
        return 1;
    }

    // print the header
    print_evtx_file_header(&fh, csv_mode);

    // decode each chunk
    for (uint32_t i = 0; i < fh.chunk_count; i++) {
//    	decode_evtx_chunk(fp, i, csv_mode);
    }
// just for testing, chunk 0 only
decode_evtx_chunk(fp, 0, csv_mode);




    // *  - walk records
//    for (uint32_t i = 0; i < fh.chunk_count; i++) {
//        walk_records(fp, &fh, i);
//    }


    fclose(fp);
    return 0;
}

