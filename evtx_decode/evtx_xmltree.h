// evtx_xmltree.h
//
// Minimal XML tree library for EVTX BinXML decoding.
// Purpose:
//   - Represent EVTX BinXML as text-style XML
//   - NOT a full XML implementation
//   - Element-only tree (no comments, CDATA, PI, etc.)
//
// Designed for forensic tools and deterministic output.
//

#ifndef EVTX_XMLTREE_H
#define EVTX_XMLTREE_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// ------------------------------------------------------------
// XML Attribute
// ------------------------------------------------------------
// Example:
//   Name="Microsoft-Windows-Servicing"
//   xmlns="http://schemas.microsoft.com/..."
//
typedef struct _XML_ATTRIBUTE {
    char *name;     // attribute name
    char *value;    // attribute value
} XML_ATTRIBUTE;


// ------------------------------------------------------------
// XML Element (node)
// ------------------------------------------------------------
// Represents a single XML element.
// - Text content is stored directly in 'text'
// - Children are ordered (as in EVTX)
// - Namespace handling is string-based only (xmlns as attribute)
//
typedef struct _XML_ELEMENT {
    char *name;                 // element name (e.g. "Event", "System")
    char *text;                 // text content (NULL if none)

    uint16_t attr_count;
    XML_ATTRIBUTE *attrs;

    // tree links
    struct _XML_ELEMENT *parent;
    struct _XML_ELEMENT *first_child;
    struct _XML_ELEMENT *last_child;
    struct _XML_ELEMENT *next_sibling;
} XML_ELEMENT;


// ------------------------------------------------------------
// XML Tree (top-level owner)
// ------------------------------------------------------------
// One XML_TREE corresponds to one EVTX record.
//
typedef struct _XML_TREE {
    XML_ELEMENT *root;          // root element (<Event>)
} XML_TREE;


// ------------------------------------------------------------
// Tree lifecycle
// ------------------------------------------------------------

/*
 * Allocate and initialize a new XML tree.
 * root is initially NULL.
 */
XML_TREE *xml_new_tree(void);

/*
 * Free the entire XML tree and all associated memory.
 */
void xml_free_tree(XML_TREE *tree);


// ------------------------------------------------------------
// Element helpers (used by BinXML decoder)
// ------------------------------------------------------------

/*
 * Create a new XML element with the given name.
 * text, attributes, and children are initialized to NULL.
 */
XML_ELEMENT *xml_new_element(const char *name);

/*
 * Append a child element to a parent element.
 * Child order is preserved.
 */
void xml_add_child(XML_ELEMENT *parent, XML_ELEMENT *child);

/*
 * Add an attribute to an element.
 * Returns 0 on success, -1 on failure.
 */
int xml_add_attribute(XML_ELEMENT *elem,
                      const char *name,
                      const char *value);




// Dump XML (pretty / compact)
void xml_dump_element(XML_ELEMENT *elem);
void xml_dump_element_compact(XML_ELEMENT *elem);

// Tree helpers
void xml_dump_tree(XML_TREE *tree);
void xml_dump_tree_compact(XML_TREE *tree);

// Search helpers
XML_ELEMENT *xml_find_child(XML_ELEMENT *parent, const char *name);


void xml_dump_tree_text(XML_TREE *tree);

#ifdef __cplusplus
}
#endif

#endif /* EVTX_XMLTREE_H */
