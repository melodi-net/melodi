/* SPDX-License-Identifier: GPL-2.0-only */
#include "mapping.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#define melodi_u8 u8
#define melodi_u32 u32
#define MELODI_U32_MAX U32_MAX
#else
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define melodi_u8 uint8_t
#define melodi_u32 uint32_t
#define MELODI_U32_MAX UINT32_MAX
#endif

struct melodi_blake2s {
    melodi_u32 hash[8];
    melodi_u32 count[2];
    melodi_u8 buffer[64];
    size_t buffered;
};

static const melodi_u32 melodi_blake2s_iv[8] = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
};

static const melodi_u8 melodi_blake2s_sigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

static melodi_u32 melodi_load32(const melodi_u8 *input)
{
    return (melodi_u32)input[0] | ((melodi_u32)input[1] << 8) |
           ((melodi_u32)input[2] << 16) | ((melodi_u32)input[3] << 24);
}

static void melodi_store32(melodi_u8 *output, melodi_u32 value)
{
    output[0] = value;
    output[1] = value >> 8;
    output[2] = value >> 16;
    output[3] = value >> 24;
}

static melodi_u32 melodi_rotate_right(melodi_u32 value, unsigned int count)
{
    return (value >> count) | (value << (32 - count));
}

static void melodi_blake2s_mix(melodi_u32 state[16], unsigned int a,
                               unsigned int b, unsigned int c,
                               unsigned int d, melodi_u32 first,
                               melodi_u32 second)
{
    state[a] = state[a] + state[b] + first;
    state[d] = melodi_rotate_right(state[d] ^ state[a], 16);
    state[c] += state[d];
    state[b] = melodi_rotate_right(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + second;
    state[d] = melodi_rotate_right(state[d] ^ state[a], 8);
    state[c] += state[d];
    state[b] = melodi_rotate_right(state[b] ^ state[c], 7);
}

static void melodi_blake2s_compress(struct melodi_blake2s *context,
                                    const melodi_u8 block[64], bool final)
{
    melodi_u32 message[16];
    melodi_u32 state[16];
    unsigned int index;
    unsigned int round;

    for (index = 0; index < 16; index++)
        message[index] = melodi_load32(block + index * 4);
    for (index = 0; index < 8; index++) {
        state[index] = context->hash[index];
        state[index + 8] = melodi_blake2s_iv[index];
    }
    state[12] ^= context->count[0];
    state[13] ^= context->count[1];
    if (final)
        state[14] = ~state[14];
    for (round = 0; round < 10; round++) {
        const melodi_u8 *order = melodi_blake2s_sigma[round];

        melodi_blake2s_mix(state, 0, 4, 8, 12,
                           message[order[0]], message[order[1]]);
        melodi_blake2s_mix(state, 1, 5, 9, 13,
                           message[order[2]], message[order[3]]);
        melodi_blake2s_mix(state, 2, 6, 10, 14,
                           message[order[4]], message[order[5]]);
        melodi_blake2s_mix(state, 3, 7, 11, 15,
                           message[order[6]], message[order[7]]);
        melodi_blake2s_mix(state, 0, 5, 10, 15,
                           message[order[8]], message[order[9]]);
        melodi_blake2s_mix(state, 1, 6, 11, 12,
                           message[order[10]], message[order[11]]);
        melodi_blake2s_mix(state, 2, 7, 8, 13,
                           message[order[12]], message[order[13]]);
        melodi_blake2s_mix(state, 3, 4, 9, 14,
                           message[order[14]], message[order[15]]);
    }
    for (index = 0; index < 8; index++)
        context->hash[index] ^= state[index] ^ state[index + 8];
}

static void melodi_blake2s_count(struct melodi_blake2s *context,
                                 melodi_u32 amount)
{
    context->count[0] += amount;
    if (context->count[0] < amount)
        context->count[1]++;
}

static void melodi_blake2s_init(struct melodi_blake2s *context)
{
    memcpy(context->hash, melodi_blake2s_iv, sizeof(context->hash));
    context->hash[0] ^= 0x01010020U;
    context->count[0] = 0;
    context->count[1] = 0;
    context->buffered = 0;
}

static void melodi_blake2s_update(struct melodi_blake2s *context,
                                  const melodi_u8 *input, size_t length)
{
    size_t amount;

    while (length != 0) {
        amount = 64 - context->buffered;
        if (amount > length)
            amount = length;
        memcpy(context->buffer + context->buffered, input, amount);
        context->buffered += amount;
        input += amount;
        length -= amount;
        if (context->buffered == 64 && length != 0) {
            melodi_blake2s_count(context, 64);
            melodi_blake2s_compress(context, context->buffer, false);
            context->buffered = 0;
        }
    }
}

static void melodi_blake2s_final(struct melodi_blake2s *context,
                                 melodi_u8 output[32])
{
    unsigned int index;

    melodi_blake2s_count(context, context->buffered);
    memset(context->buffer + context->buffered, 0, 64 - context->buffered);
    melodi_blake2s_compress(context, context->buffer, true);
    for (index = 0; index < 8; index++)
        melodi_store32(output + index * 4, context->hash[index]);
    memset(context, 0, sizeof(*context));
}

static int melodi_mapping_node_valid(const struct melodi_node_id *node_id)
{
    melodi_u8 different_zero = 0;
    melodi_u8 different_ones = 0;
    size_t index;

    if (!node_id || node_id->bytes[0] != MELODI_NODE_ID_SCHEME_ED25519)
        return 0;
    for (index = 0; index < MELODI_NODE_ID_SIZE; index++) {
        different_zero |= node_id->bytes[index];
        different_ones |= node_id->bytes[index] ^ 0xffU;
    }
    return different_zero != 0 && different_ones != 0;
}

int melodi_map_native_locator(
    const melodi_u8 domain[MELODI_MESH_DOMAIN_SIZE],
    const struct melodi_node_id *node_id,
    melodi_u32 first_round, melodi_u32 *native_locator,
    melodi_u32 *selected_round)
{
    static const melodi_u8 label[] =
        "melodi-native-locator-v1";
    struct melodi_blake2s context;
    melodi_u8 encoded_round[4];
    melodi_u8 digest[32];
    melodi_u32 candidate;
    melodi_u32 round = first_round;

    if (!domain || !melodi_mapping_node_valid(node_id) || !native_locator ||
        !selected_round)
        return -EINVAL;
    for (;;) {
        encoded_round[0] = round >> 24;
        encoded_round[1] = round >> 16;
        encoded_round[2] = round >> 8;
        encoded_round[3] = round;
        melodi_blake2s_init(&context);
        melodi_blake2s_update(&context, label, sizeof(label) - 1);
        melodi_blake2s_update(&context, domain, MELODI_MESH_DOMAIN_SIZE);
        melodi_blake2s_update(&context, node_id->bytes, MELODI_NODE_ID_SIZE);
        melodi_blake2s_update(&context, encoded_round, sizeof(encoded_round));
        melodi_blake2s_final(&context, digest);
        candidate = ((melodi_u32)digest[0] << 24) |
                    ((melodi_u32)digest[1] << 16) |
                    ((melodi_u32)digest[2] << 8) | digest[3];
        if (candidate != MELODI_NATIVE_LOCATOR_INVALID &&
            candidate != MELODI_NATIVE_LOCATOR_BROADCAST) {
            *native_locator = candidate;
            *selected_round = round;
            return 0;
        }
        if (round == MELODI_U32_MAX)
            return -EOVERFLOW;
        round++;
    }
}

int melodi_map_native_locator_available(
    const melodi_u8 domain[MELODI_MESH_DOMAIN_SIZE],
    const struct melodi_node_id *node_id, melodi_u32 first_round,
    const melodi_u32 *occupied, size_t occupied_count,
    melodi_u32 *native_locator, melodi_u32 *selected_round)
{
    melodi_u32 candidate;
    melodi_u32 round = first_round;
    size_t index;
    int error;

    if ((!occupied && occupied_count) ||
        occupied_count > MELODI_MAPPING_SET_LIMIT)
        return -EINVAL;
    for (;;) {
        error = melodi_map_native_locator(domain, node_id, round,
                                          &candidate, &round);
        if (error)
            return error;
        for (index = 0; index < occupied_count; index++)
            if (occupied[index] == candidate)
                break;
        if (index == occupied_count) {
            *native_locator = candidate;
            *selected_round = round;
            return 0;
        }
        if (round == MELODI_U32_MAX)
            return -EOVERFLOW;
        round++;
    }
}

int melodi_resolve_collision_set(
    const melodi_u8 domain[MELODI_MESH_DOMAIN_SIZE],
    const struct melodi_node_id *nodes, size_t count,
    struct melodi_mapping_entry *entries)
{
    melodi_u32 occupied[MELODI_MAPPING_SET_LIMIT];
    struct melodi_mapping_entry entry;
    size_t position;
    size_t index;
    int error;

    if (!domain || !nodes || !entries || !count ||
        count > MELODI_MAPPING_SET_LIMIT)
        return -EINVAL;
    for (index = 0; index < count; index++) {
        memset(&entry, 0, sizeof(entry));
        entry.node_id = nodes[index];
        position = index;
        while (position &&
               memcmp(entries[position - 1].node_id.bytes,
                      entry.node_id.bytes, MELODI_NODE_ID_SIZE) > 0) {
            entries[position] = entries[position - 1];
            position--;
        }
        if ((position &&
             !memcmp(entries[position - 1].node_id.bytes,
                     entry.node_id.bytes, MELODI_NODE_ID_SIZE)) ||
            (position < index &&
             !memcmp(entries[position].node_id.bytes,
                     entry.node_id.bytes, MELODI_NODE_ID_SIZE)))
            return -EEXIST;
        entries[position] = entry;
    }
    for (index = 0; index < count; index++) {
        error = melodi_map_native_locator_available(
            domain, &entries[index].node_id, 0, occupied, index,
            &entries[index].native_locator,
            &entries[index].collision_round);
        if (error)
            return error;
        occupied[index] = entries[index].native_locator;
    }
    memset(occupied, 0, sizeof(occupied));
    return 0;
}

#undef melodi_u8
#undef melodi_u32
#undef MELODI_U32_MAX
