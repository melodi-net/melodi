/* SPDX-License-Identifier: GPL-2.0-only */
#include "nodeid.h"

#include <stdint.h>
#include <string.h>
#include <sodium.h>

static const char melodi_zbase32[] = "ybndrfg8ejkmcpqxot1uwisza345h769";

static int melodi_is_uniform(const uint8_t *bytes, uint8_t value)
{
    size_t index;
    uint8_t different = 0;

    for (index = 0; index < MELODI_NODE_ID_SIZE; index++)
        different |= bytes[index] ^ value;
    return different == 0;
}

static int melodi_key_is_valid(const uint8_t key[MELODI_NODE_KEY_SIZE])
{
    return sodium_init() >= 0 && crypto_core_ed25519_is_valid_point(key) == 1;
}

int melodi_nodeid_validate(const struct melodi_node_id *node)
{
    if (!node)
        return MELODI_NODEID_INVALID;
    if (melodi_is_uniform(node->bytes, 0x00) ||
        melodi_is_uniform(node->bytes, 0xff))
        return MELODI_NODEID_INVALID;
    if (node->bytes[0] != MELODI_NODE_ID_SCHEME_ED25519)
        return MELODI_NODEID_SCHEME;
    if (!melodi_key_is_valid(node->bytes + 1))
        return MELODI_NODEID_KEY;
    return MELODI_NODEID_OK;
}

int melodi_nodeid_format(const struct melodi_node_id *node,
                         char output[MELODI_NODE_ID_STRING_SIZE])
{
    uint32_t accumulator = 0;
    unsigned int bits = 0;
    size_t input_index;
    size_t output_index = 1;
    int result;

    if (!output)
        return MELODI_NODEID_INVALID;
    result = melodi_nodeid_validate(node);
    if (result != MELODI_NODEID_OK)
        return result;
    output[0] = 'm';
    for (input_index = 0; input_index < MELODI_NODE_ID_SIZE; input_index++) {
        accumulator = (accumulator << 8) | node->bytes[input_index];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            output[output_index++] = melodi_zbase32[(accumulator >> bits) & 31];
        }
    }
    if (bits != 0)
        output[output_index++] = melodi_zbase32[(accumulator << (5 - bits)) & 31];
    output[output_index] = '\0';
    return output_index == MELODI_NODE_ID_TEXT_SIZE ? MELODI_NODEID_OK :
                                                     MELODI_NODEID_ENCODING;
}

static int melodi_zbase32_value(char character)
{
    const char *position = strchr(melodi_zbase32, character);

    return position ? (int)(position - melodi_zbase32) : -1;
}

int melodi_nodeid_parse(const char *text, size_t length,
                        struct melodi_node_id *node)
{
    uint32_t accumulator = 0;
    unsigned int bits = 0;
    size_t input_index;
    size_t output_index = 0;
    int value;
    int result;
    char canonical[MELODI_NODE_ID_STRING_SIZE];

    if (!text || !node)
        return MELODI_NODEID_INVALID;
    if (length != MELODI_NODE_ID_TEXT_SIZE || text[0] != 'm')
        return MELODI_NODEID_LENGTH;
    memset(node, 0, sizeof(*node));
    for (input_index = 1; input_index < length; input_index++) {
        value = melodi_zbase32_value(text[input_index]);
        if (value < 0)
            return MELODI_NODEID_ENCODING;
        accumulator = (accumulator << 5) | (uint32_t)value;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (output_index >= MELODI_NODE_ID_SIZE)
                return MELODI_NODEID_ENCODING;
            node->bytes[output_index++] = (uint8_t)(accumulator >> bits);
        }
    }
    if (output_index != MELODI_NODE_ID_SIZE || bits != 1 ||
        (accumulator & 1U) != 0)
        return MELODI_NODEID_ENCODING;
    result = melodi_nodeid_validate(node);
    if (result != MELODI_NODEID_OK)
        return result;
    result = melodi_nodeid_format(node, canonical);
    if (result != MELODI_NODEID_OK || memcmp(text, canonical, length) != 0)
        return MELODI_NODEID_ENCODING;
    return MELODI_NODEID_OK;
}
