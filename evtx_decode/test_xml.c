// test_xml.c
//
// Simple test program for evtx_xmltree.c APIs.
// This does NOT decode EVTX.
// It manually builds a small XML tree and tests:
//
//  - xml_new_tree()
//  - xml_new_element()
//  - xml_add_child()
//  - xml_add_attribute()
//  - xml_dump_tree()           (pretty XML)
//  - xml_dump_tree_compact()   (compact XML)
//  - xml_dump_tree_text()      (flattened text)
//  - xml_free_tree()
//
// Build the program
//    gcc -Wall -Wextra -g test_xml.c evtx_xmltree.c -o test_xml

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include "evtx_xmltree.h"

int main(void)
{
    printf("=== XML tree API test ===\n\n");

    // ------------------------------------------------------------
    // Build XML tree manually
    // ------------------------------------------------------------

    XML_TREE *tree = xml_new_tree();
    if (!tree) {
        fprintf(stderr, "xml_new_tree() failed\n");
        return 1;
    }

    // <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    XML_ELEMENT *event = xml_new_element("Event");
    xml_add_attribute(event, "xmlns",
        "http://schemas.microsoft.com/win/2004/08/events/event");
    tree->root = event;

    // <System>
    XML_ELEMENT *system = xml_new_element("System");
    xml_add_child(event, system);

    // <Provider Name="Microsoft-Windows-Servicing" Guid="{...}" />
    XML_ELEMENT *provider = xml_new_element("Provider");
    xml_add_attribute(provider, "Name", "Microsoft-Windows-Servicing");
    xml_add_attribute(provider, "Guid", "{bd12f3b8-fc40-4a61-a307-b7a013a069c1}");
    xml_add_child(system, provider);

    // <EventID>15</EventID>
    XML_ELEMENT *eventid = xml_new_element("EventID");
    eventid->text = strdup("15");
    xml_add_child(system, eventid);

    // <Execution ProcessID="4396" ThreadID="4432" />
    XML_ELEMENT *exec = xml_new_element("Execution");
    xml_add_attribute(exec, "ProcessID", "4396");
    xml_add_attribute(exec, "ThreadID", "4432");
    xml_add_child(system, exec);

    // <Computer>DESKTOP-5VCD46O</Computer>
    XML_ELEMENT *computer = xml_new_element("Computer");
    computer->text = strdup("DESKTOP-5VCD46O");
    xml_add_child(system, computer);

    // ------------------------------------------------------------
    // Test output modes
    // ------------------------------------------------------------

    printf("---- Pretty XML ----\n");
    xml_dump_tree(tree);

    printf("\n---- Compact XML ----\n");
    xml_dump_tree_compact(tree);

    printf("\n---- Flattened text ----\n");
    xml_dump_tree_text(tree);

    // ------------------------------------------------------------
    // Test xml_find_child()
    // ------------------------------------------------------------

    printf("\n---- xml_find_child() test ----\n");

    XML_ELEMENT *found = xml_find_child(system, "EventID");
    if (found && found->text) {
        printf("Found EventID: %s\n", found->text);
    } else {
        printf("EventID not found\n");
    }

    // ------------------------------------------------------------
    // Free everything
    // ------------------------------------------------------------

    xml_free_tree(tree);

    printf("\n=== test finished successfully ===\n");
    return 0;
}
