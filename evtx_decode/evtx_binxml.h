
#if !defined( EVTX_BINXML_H )
#define EVTX_BINXML_H

typedef struct {
    uint8_t *chunk_buffer;    // For Name Offset (Chunk-wide)
    uint8_t *data_ptr;        // Current position in the stream
    uint8_t *end_ptr;         // data_ptr + binxml_size (The boundary)
} BinXmlContext;


void decode_binxml(uint8_t *chunk_buffer, uint32_t binxml_offset, uint32_t binxml_size);
//void decode_binxml(uint32_t chunk_base, uint8_t *chunk_buffer, uint32_t record_base, uint8_t *binxml_offset, uint32_t binxml_size);
const char* get_value_type_name(uint8_t value_type);

void parse_binxml_stream(BinXmlContext *ctx); 

#endif
 


