/* SPDX-License-Identifier: GPL-2.0-only */
#include "mapping.h"

#include <sodium.h>

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static const uint8_t seed0[32] = { 0xfe, 0x0c };
static const uint8_t seed1[32] = { 0xbf, 0x76, 0x01 };

static const struct melodi_node_id expected0 = {
    .bytes = {
        0x01, 0x9e, 0x86, 0xf5, 0xec, 0x0c, 0x8a, 0x8b, 0x0b,
        0xd8, 0x14, 0x5d, 0xe4, 0xb1, 0x7c, 0xe7, 0x0c,
        0x50, 0xfd, 0x96, 0xb0, 0x89, 0xfe, 0x2d, 0x78, 0x3e,
        0x6b, 0x41, 0xbc, 0x5a, 0xfa, 0xa6, 0xf6,
    },
};

static const struct melodi_node_id expected1 = {
    .bytes = {
        0x01, 0x51, 0x2a, 0x77, 0x56, 0x1a, 0xea, 0x3d, 0x16,
        0x28, 0x32, 0x91, 0xdf, 0xd8, 0x92, 0xbb, 0x92,
        0xc9, 0xc4, 0x53, 0x8e, 0xba, 0xdf, 0x65, 0x7b, 0x79,
        0x08, 0xd6, 0x40, 0x26, 0x89, 0xaf, 0xdd,
    },
};

static void derive(const uint8_t seed[32], struct melodi_node_id *node_id)
{
    uint8_t secret_key[crypto_sign_SECRETKEYBYTES];

    node_id->bytes[0] = MELODI_NODE_ID_SCHEME_ED25519;
    assert(crypto_sign_seed_keypair(node_id->bytes + 1, secret_key,
                                    seed) == 0);
    sodium_memzero(secret_key, sizeof(secret_key));
}

static int write_identity(const char *path, const uint8_t seed[32])
{
    ssize_t written;
    int descriptor;

    descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (descriptor < 0)
        return -1;
    written = write(descriptor, seed, 32);
    if (close(descriptor) < 0 || written != 32) {
        unlink(path);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct melodi_mapping_entry entries[2];
    struct melodi_mapping_entry reversed_entries[2];
    struct melodi_node_id nodes[2];
    struct melodi_node_id reversed[2];
    uint8_t domain[MELODI_MESH_DOMAIN_SIZE] = { 0 };
    uint32_t native_locator;
    uint32_t round;

    assert(argc == 1 || argc == 3);
    assert(sodium_init() >= 0);
    derive(seed0, &nodes[0]);
    derive(seed1, &nodes[1]);
    assert(memcmp(&nodes[0], &expected0, sizeof(expected0)) == 0);
    assert(memcmp(&nodes[1], &expected1, sizeof(expected1)) == 0);
    assert(melodi_map_native_locator(
               domain, &nodes[0], 0, &native_locator, &round) == 0);
    assert(native_locator == 0xa1d47091U && round == 0);
    assert(melodi_map_native_locator(
               domain, &nodes[1], 0, &native_locator, &round) == 0);
    assert(native_locator == 0xa1d47091U && round == 0);
    assert(melodi_resolve_collision_set(domain, nodes, 2, entries) == 0);
    assert(entries[0].native_locator == 0xa1d47091U);
    assert(entries[0].collision_round == 0);
    assert(entries[1].native_locator == 0x02662aceU);
    assert(entries[1].collision_round == 1);
    reversed[0] = nodes[1];
    reversed[1] = nodes[0];
    assert(melodi_resolve_collision_set(domain, reversed, 2,
                                        reversed_entries) == 0);
    assert(memcmp(entries, reversed_entries, sizeof(entries)) == 0);
    if (argc == 3) {
        if (write_identity(argv[1], seed0))
            return 1;
        if (write_identity(argv[2], seed1)) {
            unlink(argv[1]);
            return 1;
        }
    }
    return 0;
}
