/* main.c
 *
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "evtx_file.h"
#include "evtx_chunk.h"

#include "output.h"

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-x|--xml] [-t|--txt] [-d|--dump] file.evtx [EventID]\n", prog);
}


int main(int argc, char **argv)
{
    const char *filename = NULL;
    uint16_t output_mode = OUTPUT_TSV;  // default mode
    uint16_t target_event_id = 0;

    /* ---- argument parse  ---- */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dump") == 0) {
            output_mode = output_mode | OUTPUT_DUMP;
        } else if (strcmp(argv[i], "-x") == 0 || strcmp(argv[i], "--xml") == 0) {
            output_mode = output_mode | OUTPUT_XML;
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--txt") == 0) {
            output_mode = output_mode | OUTPUT_TXT;
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

    /* ---- file open ---- */
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    // read file header
    EVTX_FILE_HEADER fh;
    fread(&fh, sizeof(fh), 1, fp);

    // decode the evtx file header then decode each chunk 
    if (decode_evtx_file_header(fp, &fh, output_mode) == 0) {

        ////DEBUG ONLY
        ////fh.chunk_count = 1;

        for (uint16_t i = 0; i < fh.chunk_count; i++) {
            decode_evtx_chunk(fp, i, output_mode);
        }
    } else {
        fclose(fp);
        return 1;
    }

    fclose(fp);
    return 0;
}

