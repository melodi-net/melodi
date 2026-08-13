/* SPDX-License-Identifier: GPL-2.0-only */
#include "nodeid.h"

#include <assert.h>
#include <string.h>

static const struct melodi_node_id valid_node = {
    .bytes = {
        0x01, 0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    },
};

static void test_roundtrip(void)
{
    struct melodi_node_id parsed;
    char text[MELODI_NODE_ID_STRING_SIZE];

    assert(melodi_nodeid_validate(&valid_node) == MELODI_NODEID_OK);
    assert(melodi_nodeid_format(&valid_node, text) == MELODI_NODEID_OK);
    assert(strlen(text) == MELODI_NODE_ID_TEXT_SIZE);
    assert(melodi_nodeid_parse(text, strlen(text), &parsed) == MELODI_NODEID_OK);
    assert(memcmp(&parsed, &valid_node, sizeof(parsed)) == 0);
}

static void test_invalid(void)
{
    struct melodi_node_id node = valid_node;
    struct melodi_node_id parsed;
    char text[MELODI_NODE_ID_STRING_SIZE];

    memset(&node, 0, sizeof(node));
    assert(melodi_nodeid_validate(&node) == MELODI_NODEID_INVALID);
    memset(&node, 0xff, sizeof(node));
    assert(melodi_nodeid_validate(&node) == MELODI_NODEID_INVALID);
    node = valid_node;
    node.bytes[0] = 2;
    assert(melodi_nodeid_validate(&node) == MELODI_NODEID_SCHEME);
    node = valid_node;
    memset(node.bytes + 1, 0xff, MELODI_NODE_KEY_SIZE);
    assert(melodi_nodeid_validate(&node) == MELODI_NODEID_KEY);
    node = valid_node;
    memset(node.bytes + 1, 0, MELODI_NODE_KEY_SIZE);
    assert(melodi_nodeid_validate(&node) == MELODI_NODEID_KEY);
    assert(melodi_nodeid_format(&valid_node, text) == MELODI_NODEID_OK);
    text[0] = 'M';
    assert(melodi_nodeid_parse(text, strlen(text), &parsed) != MELODI_NODEID_OK);
    assert(melodi_nodeid_format(&valid_node, text) == MELODI_NODEID_OK);
    text[10] = '0';
    assert(melodi_nodeid_parse(text, strlen(text), &parsed) == MELODI_NODEID_ENCODING);
    assert(melodi_nodeid_format(&valid_node, text) == MELODI_NODEID_OK);
    text[MELODI_NODE_ID_TEXT_SIZE - 1] = 'b';
    assert(melodi_nodeid_parse(text, strlen(text), &parsed) == MELODI_NODEID_ENCODING);
}

int main(void)
{
    test_roundtrip();
    test_invalid();
    return 0;
}
