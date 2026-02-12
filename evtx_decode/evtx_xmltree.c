// evtx_xmltree.c
//
// Minimal XML tree library for EVTX BinXML decoding.
// NOT a full XML implementation.
//
// Memory model:
//   - xml_new_tree() allocates an empty tree (root=NULL)
//   - xml_new_element() allocates a node and duplicates strings
//   - xml_add_attribute() appends to a dynamic array
//   - xml_add_child() appends child in O(1) using last_child
//   - xml_free_tree() frees everything recursively
//

#include "evtx_xmltree.h"

#include <string.h>   // strlen, memcpy
#include <stdio.h>    // optional (not required), but handy for debugging

#define BINXML_VALUE_NULL 0x00

// -------------------------
// Internal helpers
// -------------------------

static void xml_dump_indent(int depth)
{
    for (int i = 0; i < depth; i++)
        fputs("  ", stdout);
}


static void xml_dump_attrs(XML_ELEMENT *e)
{
    for (uint16_t i = 0; i < e->attr_count; i++) {
        XML_ATTRIBUTE *a = &e->attrs[i];


        // NULL value type は出力しない（EventViewerの <Correlation /> など）
        if (a->value_type == BINXML_VALUE_NULL) {
            //printf("\nDEBUG: Attribute Name:%s Value:\"%s\" value_type=0x%x\n", a->name, a->value, a->value_type);
            continue;
        }

        // 値が無い/壊れてるケースも念のため skip
        if (!a->name || !a->value) {
            continue;
        }

        printf(" %s=\"%s\"", a->name, a->value);
    }
}


static char *xml_strdup(const char *s)
{
    if (!s) return NULL;
    size_t n = strlen(s);
    char *p = (char *)malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}


static void xml_free_element(XML_ELEMENT *elem)
{
    if (!elem) return;

    // free children
    XML_ELEMENT *child = elem->first_child;
    while (child) {
        XML_ELEMENT *next = child->next_sibling;
        xml_free_element(child);
        child = next;
    }

    // free attributes
    for (uint16_t i = 0; i < elem->attr_count; i++) {
        free(elem->attrs[i].name);
        free(elem->attrs[i].value);
    }
    free(elem->attrs);

    // free strings
    free(elem->name);
    free(elem->text);

    // free element itself
    free(elem);
}

static void xml_dump_element_pretty(XML_ELEMENT *e, int depth)
{
    if (!e) return;

    xml_dump_indent(depth);
    printf("<%s", e->name);
    xml_dump_attrs(e);

    // self-closing
    if (!e->first_child && !e->text) {
        puts(" />");
        return;
    }

    puts(">");

    // text
    if (e->text) {
        xml_dump_indent(depth + 1);
        puts(e->text);
    }

    // children
    for (XML_ELEMENT *c = e->first_child; c; c = c->next_sibling) {
        xml_dump_element_pretty(c, depth + 1);
    }

    xml_dump_indent(depth);
    printf("</%s>\n", e->name);
}

static void xml_dump_element(XML_ELEMENT *elem)
{
    xml_dump_element_pretty(elem, 0);
}

static void xml_dump_element_compact_rec(XML_ELEMENT *e)
{
    if (!e) return;

    printf("<%s", e->name);
    xml_dump_attrs(e);

    if (!e->first_child && !e->text) {
        printf("/>");
        return;
    }

    printf(">");

    if (e->text)
        fputs(e->text, stdout);

    for (XML_ELEMENT *c = e->first_child; c; c = c->next_sibling)
        xml_dump_element_compact_rec(c);

    printf("</%s>", e->name);
}


static void xml_print_attribute(const XML_ATTRIBUTE *a)
{
    if (!a) return;

    if (a->value_type == BINXML_VALUE_NULL) {
        return; // ← 出力しない
    }

    printf(" %s=\"%s\"", a->name, a->value);
}


static void xml_print_text(const XML_ELEMENT *e)
{
    if (!e || !e->text) return;

    if (e->text_type == BINXML_VALUE_NULL) {
        return;
    }

    printf("%s", e->text);
}



static void xml_dump_element_compact(XML_ELEMENT *elem)
{
    xml_dump_element_compact_rec(elem);
    putchar('\n');
}


static void xml_emit_kv(const char *key, const char *value)
{
    if (!key || !value) return;
    printf("%s: %s\n", key, value);
}

static void xml_dump_element_text(XML_ELEMENT *e)
{
    if (!e) return;

    // 1) element text
    if (e->text && e->text[0] != '\0') {
        xml_emit_kv(e->name, e->text);
    }

    // 2) attributes
    for (uint16_t i = 0; i < e->attr_count; i++) {
        char key[512];

        snprintf(key, sizeof(key),
                 "%s.%s", e->name, e->attrs[i].name);

        xml_emit_kv(key, e->attrs[i].value);
    }

    // 3) children
    for (XML_ELEMENT *c = e->first_child; c; c = c->next_sibling) {
        xml_dump_element_text(c);
    }
}








// -------------------------
// Public APIs for XML_ATTRIBUTE
// -------------------------

XML_ATTRIBUTE *xml_new_attribute(const char *name)
{
    if (!name)
        return NULL;

    XML_ATTRIBUTE *a = (XML_ATTRIBUTE *)calloc(1, sizeof(XML_ATTRIBUTE));
    if (!a)
        return NULL;

    a->name = xml_strdup(name);
    if (!a->name) {
        free(a);
        return NULL;
    }

    a->value = NULL;
    a->value_type = 0xFF;   // undefined yet

    return a;
}

int xml_set_attribute(XML_ATTRIBUTE *attr, const char *value, uint8_t value_type)
{
    if (!attr)
        return -1;

    // free previous value if any
    if (attr->value) {
        free(attr->value);
        attr->value = NULL;
    }

    attr->value_type = value_type;

    if (value_type != 0x00 && value) {   // 0x00 = NULL type
        attr->value = xml_strdup(value);
        if (!attr->value)
            return -1;
    } else {
        attr->value = NULL;
    }

    return 0;
}









// -------------------------
// Public APIs for XML_ELEMENT
// -------------------------

XML_ELEMENT *xml_new_element(const char *name)
{
    if (!name) return NULL;

    XML_ELEMENT *e = (XML_ELEMENT *)calloc(1, sizeof(XML_ELEMENT));
    if (!e) return NULL;

    e->name = xml_strdup(name);
    if (!e->name) {
        free(e);
        return NULL;
    }

    // text=NULL, attrs=NULL, counts=0, links=NULL by calloc
    return e;
}


int xml_set_element(XML_ELEMENT *elem, const char *text, uint8_t text_type)
{
    if (!elem) return -1;

    if (elem->text) {
        free(elem->text);
        elem->text = NULL;
    }

    elem->text_type = text_type;

    if (text_type == BINXML_VALUE_NULL || !text) {
        elem->text = NULL;
        return 0;
    }

    elem->text = xml_strdup(text);
    return (elem->text != NULL) ? 0 : -1;
}


int xml_add_attribute(XML_ELEMENT *elem, XML_ATTRIBUTE *attr)
{
    if (!elem || !attr)
        return -1;

    XML_ATTRIBUTE *new_attrs =
        (XML_ATTRIBUTE *)realloc(elem->attrs,
                                 (elem->attr_count + 1) * sizeof(XML_ATTRIBUTE));
    if (!new_attrs)
        return -1;

    elem->attrs = new_attrs;

    // Copy struct contents (shallow copy is OK —
    // name/value pointers move into element ownership)
    elem->attrs[elem->attr_count] = *attr;

    elem->attr_count++;

    // free only container struct, not name/value
    free(attr);

    return 0;
}


void xml_add_child(XML_ELEMENT *parent, XML_ELEMENT *child)
{
    if (!parent || !child) return;

    // detach child's sibling pointer just in case caller reuses nodes
    child->next_sibling = NULL;
    child->parent = parent;

    if (!parent->first_child) {
        parent->first_child = child;
        parent->last_child  = child;
    } else {
        parent->last_child->next_sibling = child;
        parent->last_child = child;
    }
}


XML_ELEMENT *xml_find_child(XML_ELEMENT *parent, const char *name)
{
    if (!parent || !name) return NULL;

    for (XML_ELEMENT *c = parent->first_child; c; c = c->next_sibling) {
        if (strcmp(c->name, name) == 0)
            return c;
    }
    return NULL;
}




// -------------------------
// Public APIs for XML_TREE
// -------------------------
XML_TREE *xml_new_tree(void)
{
    XML_TREE *t = (XML_TREE *)calloc(1, sizeof(XML_TREE));
    // calloc initializes root=NULL
    return t;
}

void xml_free_tree(XML_TREE *tree)
{
    if (!tree) return;
    xml_free_element(tree->root);
    free(tree);
}

void xml_dump_tree(XML_TREE *tree)
{
    if (!tree || !tree->root) return;
    xml_dump_element(tree->root);
}

void xml_dump_tree_compact(XML_TREE *tree)
{
    if (!tree || !tree->root) return;
    xml_dump_element_compact(tree->root);
}


void xml_dump_tree_text(XML_TREE *tree)
{
    if (!tree || !tree->root) return;
    xml_dump_element_text(tree->root);
}







