/* SPDX-License-Identifier: GPL-2.0-only */
#include "mapping.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

static const struct melodi_node_id node = {
    .bytes = {
        0x01, 0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    },
};

int main(void)
{
    struct melodi_mapping_entry first[3];
    struct melodi_mapping_entry second[3];
    struct melodi_node_id nodes[3] = { node, node, node };
    struct melodi_node_id reversed[3];
    uint8_t domain[MELODI_MESH_DOMAIN_SIZE] = { 0 };
    uint32_t occupied[2];
    uint32_t native_locator;
    uint32_t round;

    assert(melodi_map_native_locator(
               domain, &node, 0, &native_locator, &round) == 0);
    assert(native_locator == 0x3681f059U);
    assert(round == 0);
    memset(domain, 0xa5, sizeof(domain));
    assert(melodi_map_native_locator(
               domain, &node, 7, &native_locator, &round) == 0);
    assert(native_locator == 0xce59d585U);
    assert(round == 7);
    memset(domain, 0, sizeof(domain));
    occupied[0] = 0x3681f059U;
    assert(melodi_map_native_locator_available(
               domain, &node, 0, occupied, 1, &native_locator,
               &round) == 0);
    assert(native_locator != occupied[0]);
    assert(round > 0);
    occupied[1] = native_locator;
    assert(melodi_map_native_locator_available(
               domain, &node, 0, occupied, 2, &native_locator,
               &round) == 0);
    assert(native_locator != occupied[0] &&
           native_locator != occupied[1]);
    assert(round > 1);
    nodes[1].bytes[32] ^= 0x55;
    nodes[2].bytes[31] ^= 0xaa;
    reversed[0] = nodes[2];
    reversed[1] = nodes[1];
    reversed[2] = nodes[0];
    assert(melodi_resolve_collision_set(domain, nodes, 3, first) == 0);
    assert(melodi_resolve_collision_set(domain, reversed, 3, second) == 0);
    assert(memcmp(first, second, sizeof(first)) == 0);
    assert(first[0].native_locator != first[1].native_locator);
    assert(first[0].native_locator != first[2].native_locator);
    assert(first[1].native_locator != first[2].native_locator);
    nodes[1] = nodes[0];
    assert(melodi_resolve_collision_set(domain, nodes, 3, first) == -EEXIST);
    return 0;
}
