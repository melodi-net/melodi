/* SPDX-License-Identifier: GPL-2.0-only */
#include "monocypher-ed25519.h"
#include "wire.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

static const uint8_t seed_vector[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

static void test_broadcast_data(const uint8_t secret_key[64],
                                const uint8_t public_key[32])
{
    static const uint8_t content[] = { 1, 2, 3, 4, 5 };
    struct melodi_wire_data decoded;
    struct melodi_wire_data header = { 0 };
    uint8_t decoded_signature[MELODI_WIRE_SIGNATURE_SIZE];
    uint8_t signature[MELODI_WIRE_SIGNATURE_SIZE] = { 0 };
    uint8_t signing[MELODI_WIRE_BROADCAST_AUTH_SIZE + sizeof(content)];
    uint8_t frame[MELODI_WIRE_DATA_SIZE + MELODI_WIRE_BROADCAST_OVERHEAD +
                  sizeof(content)];
    const uint8_t *payload;
    size_t payload_length;
    size_t frame_length;

    header.common.flags = MELODI_WIRE_F_BROADCAST | MELODI_WIRE_F_FINAL;
    header.common.source_native_locator = 0x3681f059U;
    header.common.destination_native_locator =
        MELODI_NATIVE_LOCATOR_BROADCAST;
    header.common.identity_generation = 1;
    header.common.message_id = 2;
    header.common.counter = 4;
    header.source_service = 1234;
    header.destination_service = 4321;
    header.fragment_count = 1;
    header.logical_length = sizeof(content);
    assert(melodi_wire_encode_broadcast_data(
               frame, sizeof(frame), &header, signature, content,
               sizeof(content), &frame_length) == 0);
    memcpy(signing, frame, MELODI_WIRE_BROADCAST_AUTH_SIZE);
    memcpy(signing + MELODI_WIRE_BROADCAST_AUTH_SIZE, content,
           sizeof(content));
    crypto_ed25519_sign(signature, secret_key, signing, sizeof(signing));
    memcpy(frame + 60, signature, MELODI_WIRE_TAG_SIZE);
    memcpy(frame + MELODI_WIRE_DATA_SIZE,
           signature + MELODI_WIRE_TAG_SIZE,
           MELODI_WIRE_BROADCAST_SIGNATURE_SUFFIX_SIZE);
    assert(melodi_wire_decode_broadcast_data(
               frame, frame_length, &decoded, decoded_signature, &payload,
               &payload_length) == 0);
    memcpy(signing, frame, MELODI_WIRE_BROADCAST_AUTH_SIZE);
    memcpy(signing + MELODI_WIRE_BROADCAST_AUTH_SIZE, payload,
           payload_length);
    assert(crypto_ed25519_check(decoded_signature, public_key, signing,
                                sizeof(signing)) == 0);
    signing[sizeof(signing) - 1] ^= 1;
    assert(crypto_ed25519_check(decoded_signature, public_key, signing,
                                sizeof(signing)) != 0);
}

static void test_control(const uint8_t secret_key[64],
                         const uint8_t public_key[32],
                         const struct melodi_node_id *node_id)
{
    struct melodi_wire_control decoded;
    struct melodi_wire_control control = { 0 };
    uint8_t frame[MELODI_WIRE_CONTROL_SIZE];

    control.common.flags = MELODI_WIRE_F_BROADCAST;
    control.common.source_native_locator = 0x3681f059U;
    control.common.destination_native_locator =
        MELODI_NATIVE_LOCATOR_BROADCAST;
    control.common.identity_generation = 1;
    control.common.message_id = 5;
    control.common.counter = 6;
    control.node_id = *node_id;
    control.opcode = MELODI_CONTROL_PROBE;
    assert(melodi_wire_encode_control(frame, &control) == 0);
    crypto_ed25519_sign(control.signature, secret_key, frame,
                        MELODI_WIRE_CONTROL_SIGNED_SIZE);
    memcpy(frame + MELODI_WIRE_CONTROL_SIGNED_SIZE, control.signature,
           sizeof(control.signature));
    assert(melodi_wire_decode_control(frame, sizeof(frame), &decoded) == 0);
    assert(crypto_ed25519_check(decoded.signature, public_key, frame,
                                MELODI_WIRE_CONTROL_SIGNED_SIZE) == 0);
    frame[113] ^= 1;
    assert(crypto_ed25519_check(decoded.signature, public_key, frame,
                                MELODI_WIRE_CONTROL_SIGNED_SIZE) != 0);
}

int main(void)
{
    struct melodi_wire_hello decoded;
    struct melodi_wire_hello hello = { 0 };
    uint8_t secret_key[64];
    uint8_t public_key[32];
    uint8_t frame[MELODI_WIRE_HELLO_SIZE];
    uint8_t seed[32];

    memcpy(seed, seed_vector, sizeof(seed));
    crypto_ed25519_key_pair(secret_key, public_key, seed);
    hello.common.flags = MELODI_WIRE_F_BROADCAST;
    hello.common.source_native_locator = 0x3681f059U;
    hello.common.destination_native_locator =
        MELODI_NATIVE_LOCATOR_BROADCAST;
    hello.common.identity_generation = 1;
    hello.common.message_id = 2;
    hello.common.counter = 3;
    hello.node_id.bytes[0] = MELODI_NODE_ID_SCHEME_ED25519;
    memcpy(hello.node_id.bytes + 1, public_key, sizeof(public_key));
    hello.expiry_seconds = 300;
    assert(melodi_wire_encode_hello(frame, &hello) == 0);
    crypto_ed25519_sign(hello.signature, secret_key, frame,
                        MELODI_WIRE_HELLO_SIGNED_SIZE);
    memcpy(frame + MELODI_WIRE_HELLO_SIGNED_SIZE, hello.signature,
           sizeof(hello.signature));
    assert(melodi_wire_decode_hello(frame, sizeof(frame), &decoded) == 0);
    assert(crypto_ed25519_check(decoded.signature, public_key, frame,
                                MELODI_WIRE_HELLO_SIGNED_SIZE) == 0);
    frame[105] ^= 1;
    assert(crypto_ed25519_check(decoded.signature, public_key, frame,
                                MELODI_WIRE_HELLO_SIGNED_SIZE) != 0);
    frame[105] ^= 1;
    assert(melodi_wire_encode_conflict(frame, &hello) == 0);
    crypto_ed25519_sign(hello.signature, secret_key, frame,
                        MELODI_WIRE_HELLO_SIGNED_SIZE);
    memcpy(frame + MELODI_WIRE_HELLO_SIGNED_SIZE, hello.signature,
           sizeof(hello.signature));
    assert(melodi_wire_decode_conflict(frame, sizeof(frame), &decoded) == 0);
    assert(crypto_ed25519_check(decoded.signature, public_key, frame,
                                MELODI_WIRE_HELLO_SIGNED_SIZE) == 0);
    test_broadcast_data(secret_key, public_key);
    test_control(secret_key, public_key, &hello.node_id);
    return 0;
}
