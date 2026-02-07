#if !defined( OUTPUT_H )
#define OUTPUT_H


#define OUTPUT_TSV      0x01
#define OUTPUT_XML      0x02
#define OUTPUT_TXT      0x04
#define OUTPUT_R1       0x08
#define OUTPUT_R2       0x10
#define OUTPUT_R3       0x20
#define OUTPUT_R4       0x40
#define OUTPUT_DUMP     0x80




// low 16 bits
#define OUT_CSV     0x0001
#define OUT_TXT     0x0002
#define OUT_XML     0x0004
#define OUT_SCHEMA  0x0008

// masks
#define OUT_MODE_MASK   0x0000FFFF
#define EVTID_MASK      0xFFFF0000

// helpers
#define SET_EVTID(x)    ((uint32_t)(x) << 16)
#define GET_EVTID(x)    (((x) >> 16) & 0xFFFF)
#define GET_OUTMODE(x) ((x) & OUT_MODE_MASK)





#endif
