/* SPDX-License-Identifier: GPL-2.0-only */
#include "monocypher-ed25519.h"
#include "monocypher.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sodium.h>

static const uint8_t seed_vector[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static const uint8_t public_vector[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
};

static const uint8_t signature_vector[64] = {
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
    0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
    0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
    0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
    0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
    0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
    0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
};

static uint64_t next_value(uint64_t *state)
{
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    return *state;
}

static void test_public_key_validation(void)
{
    uint64_t state = UINT64_C(0x123456789abcdef0);
    uint8_t public_key[32];
    unsigned int sample;
    unsigned int index;

    assert(sodium_init() >= 0);
    for (sample = 0; sample < 512; sample++) {
        for (index = 0; index < sizeof(public_key); index += 8) {
            uint64_t value = next_value(&state);

            memcpy(public_key + index, &value, sizeof(value));
        }
        assert((crypto_eddsa_public_key_check(public_key) == 0) ==
               (crypto_core_ed25519_is_valid_point(public_key) == 1));
    }
}

int main(void)
{
    uint8_t secret_key[64];
    uint8_t public_key[32];
    uint8_t signature[64];
    uint8_t seed[32];

    memcpy(seed, seed_vector, sizeof(seed));
    crypto_ed25519_key_pair(secret_key, public_key, seed);
    assert(memcmp(public_key, public_vector, sizeof(public_key)) == 0);
    crypto_ed25519_sign(signature, secret_key, NULL, 0);
    assert(memcmp(signature, signature_vector, sizeof(signature)) == 0);
    assert(crypto_ed25519_check(signature, public_key, NULL, 0) == 0);
    assert(crypto_eddsa_public_key_check(public_key) == 0);
    memset(public_key, 0, sizeof(public_key));
    assert(crypto_eddsa_public_key_check(public_key) != 0);
    public_key[0] = 1;
    assert(crypto_eddsa_public_key_check(public_key) != 0);
    signature[0] ^= 1;
    assert(crypto_ed25519_check(signature, public_vector, NULL, 0) != 0);
    test_public_key_validation();
    return 0;
}
