
#include <stdio.h>
#include <stdlib.h>

#include "evtx_output.h"
#include "evtx_xmltree.h"


void output_xmltree(XML_TREE *xtree, uint32_t output_mode) 
{

    if (IS_OUT_DEFAULT(output_mode)) {
        //printf("DEBUG: output_xmltree(): DEFAULT\n");
    }

    if (CHECK_OUTMODE(output_mode, OUT_DEBUG)) {
//        printf("DEBUG: output_xmltree(): DEBUG\n");
    }

    if (CHECK_OUTMODE(output_mode, OUT_CSV)) {
//        printf("DEBUG: output_xmltree(): CSV\n");
    }

    if (CHECK_OUTMODE(output_mode, OUT_XML)) {
//        printf("DEBUG: output_xmltree(): XML\n");
    }

    if (CHECK_OUTMODE(output_mode, OUT_TXT)) {
//        printf("DEBUG: output_xmltree(): TXT\n");
    }

    if (CHECK_OUTMODE(output_mode, OUT_SCHEMA)) {
//        printf("DEBUG: output_xmltree(): SCHEMA\n");
    }
}
