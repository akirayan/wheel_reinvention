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




int decode_evtx_record(uint32_t chunk_base, uint32_t record_base, uint8_t *chunk_buffer, uint32_t output_mode)
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

    if (IS_OUT_DEFAULT(output_mode)) {
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
    }

    // decode binxml 
    uint32_t binxml_offset = record_base + sizeof(EVTX_RECORD_HEADER);
    uint32_t binxml_size = rh->record_size - sizeof(EVTX_RECORD_HEADER) - sizeof(uint32_t); 
                               // the lastt 4B is record_size_COPY, so we do not calculate it 
    if (CHECK_OUTMODE(output_mode, OUT_DEBUG)) {
        printf("DEBUG: called from decode_evtx_record()\t"); 
    }


    // create the XMLTREE object for this record
    XML_TREE *xtree = xml_new_tree();

    // let decode_binxml to build th XMLTREE
    decode_binxml(chunk_buffer, binxml_offset, binxml_size, output_mode, xtree);

    // output the XMLTREE
    output_xmltree(xtree, output_mode);  

    // finally free the tree
    xml_free_tree(xtree);

    return 0;
}


