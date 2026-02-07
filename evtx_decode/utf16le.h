/*
 * utf16le.h
 *
 */

#if !defined( UTF16LE_H )
#define UTF16LE_H



void print_utf16le_string(uint16_t char_count, uint16_t *utf16le_data);
//void print_name_from_offset(FILE *fp, uint32_t chunk_base, uint32_t name_offset);
void print_name_from_offset_buffer(uint8_t *chunk_buffer, uint32_t name_offset);



 
#endif

