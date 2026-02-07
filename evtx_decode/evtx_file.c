/* evtx_file.c
 *
 *
 */


#include <stdio.h>
#include <string.h>

#include "evtx_file.h"
#include "hex_dump.h"
#include "output.h"

// verify and decode the evtx file header
int decode_evtx_file_header(FILE *fp, EVTX_FILE_HEADER *fh, int output_mode)
{

    // verify the signature first
    if (memcmp(fh->signature, EVTX_FILE_SIGNATURE, sizeof(EVTX_FILE_SIGNATURE)) == 0) {
        if (output_mode & OUTPUT_TSV) {

            // print the contents of head
            printf("%.8s", fh->signature);
            printf("\t      version=%u.%u", fh->major_version, fh->minor_version);
            printf("\tchunk=%" PRIu64 "-%" PRIu64 "", fh->first_chunk_number, fh->last_chunk_number);
            printf("\tchunk_counts=%" PRIu16 "", fh->chunk_count);
            //printf("\tchunk_offset=0x%08" PRIx16 "", fh->header_block_size);
            printf("\tnext_record_id=%" PRIu64 "", fh->next_record_id);
            printf("\tflags=0x%02" PRIx32 "", fh->flags);
            { // flags as text
                char ftext[8]; 
                switch (fh->flags) {
                    case 0x00: strcpy(ftext, "clean"); break;;
                    case 0x01: strcpy(ftext, "dirty"); break;;
                    case 0x02: strcpy(ftext, "full"); break;;
                    default  : strcpy(ftext, "unknown"); break;;
                }
                printf("(%s)", ftext);
            }
            //printf("\theader_size=%" PRIu32 "", fh->header_size);
            printf("\n");

        } 
        if (output_mode & OUTPUT_DUMP) {
            uint32_t offset = 0x00000000; // the starting of this file
            hex_dump_file(fp, offset, fh->header_size);
        }
	

    } else {
        fprintf(stderr, "Invalid EVTX signature\n");
        return 1;
    }

    return 0;
}

