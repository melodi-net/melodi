/* SPDX-License-Identifier: GPL-2.0-only */
#include "wire.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

static const uint8_t expected[] = {
    0x01, 0x04, 0x00, 0x1e, 0x00, 0x50, 0x00, 0x03,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x00, 0x00, 0x00, 0x09, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x00, 0x00, 0x00, 0x00,
    0x12, 0x34, 0xab, 0xcd, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x03, 0x02, 0x03, 0x00, 0x00,
    0x89, 0xab, 0xcd, 0xef, 0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x00, 0x00, 0x00,
    0xaa, 0xbb, 0xcc,
};

static const uint8_t expected_ack[] = {
    0x01, 0x05, 0x00, 0x02, 0x00, 0x48, 0x00, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x00, 0x00, 0x00, 0x0a, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x09, 0x00, 0x03, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static const uint8_t expected_broadcast[] = {
    0x01, 0x04, 0x00, 0x11, 0x00, 0x50, 0x00, 0x32,
    0x11, 0x22, 0x33, 0x44, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x09, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x00, 0x00, 0x00, 0x00,
    0x12, 0x34, 0xab, 0xcd, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0xaa, 0xbb,
};

static struct melodi_wire_data vector_header(void)
{
    struct melodi_wire_data header = { 0 };
    unsigned int index;

    header.common.flags = MELODI_WIRE_F_ENCRYPTED |
                          MELODI_WIRE_F_RELIABLE |
                          MELODI_WIRE_F_ORDERED |
                          MELODI_WIRE_F_FINAL;
    header.common.source_native_locator = 0x11223344U;
    header.common.destination_native_locator = 0x55667788U;
    header.common.identity_generation = 9;
    header.common.message_id = UINT64_C(0x0102030405060708);
    header.common.counter = UINT64_C(0x1112131415161718);
    header.destination_service = 0x1234;
    header.source_service = 0xabcd;
    header.fragment_count = 1;
    header.logical_length = 3;
    header.delivery_mode = MELODI_DELIVERY_RELIABLE_ORDERED;
    header.priority = 3;
    header.ordering_marker = 0x89abcdefU;
    for (index = 0; index < MELODI_WIRE_TAG_SIZE; index++)
        header.tag[index] = index;
    return header;
}

static void test_ack(void)
{
    struct melodi_wire_ack decoded;
    struct melodi_wire_ack ack = { 0 };
    uint8_t encoded[MELODI_WIRE_ACK_SIZE];
    unsigned int index;

    ack.common.flags = MELODI_WIRE_F_ENCRYPTED;
    ack.common.source_native_locator = 0x11223344U;
    ack.common.destination_native_locator = 0x55667788U;
    ack.common.identity_generation = 10;
    ack.common.message_id = UINT64_C(0x0102030405060708);
    ack.common.counter = UINT64_C(0x1112131415161718);
    ack.acknowledged_generation = 9;
    ack.fragment_count = 3;
    ack.status = MELODI_ACK_COMPLETE;
    ack.bitmap = 7;
    for (index = 0; index < sizeof(ack.tag); index++)
        ack.tag[index] = index + 0x10;
    assert(melodi_wire_encode_ack(encoded, &ack) == 0);
    assert(memcmp(encoded, expected_ack, sizeof(expected_ack)) == 0);
    assert(melodi_wire_decode_ack(encoded, sizeof(encoded), &decoded) == 0);
    assert(decoded.bitmap == 7);
    encoded[47] = 1;
    assert(melodi_wire_decode_ack(encoded, sizeof(encoded), &decoded) ==
           -EPROTO);
    encoded[47] = 0;
    encoded[55] = 8;
    assert(melodi_wire_decode_ack(encoded, sizeof(encoded), &decoded) ==
           -EPROTO);
}

static void test_broadcast(void)
{
    static const uint8_t payload_bytes[] = { 0xaa, 0xbb };
    struct melodi_wire_data header = vector_header();
    struct melodi_wire_data decoded;
    uint8_t decoded_signature[MELODI_WIRE_SIGNATURE_SIZE];
    uint8_t signature[MELODI_WIRE_SIGNATURE_SIZE];
    uint8_t encoded[sizeof(expected_broadcast)];
    const uint8_t *payload;
    size_t payload_length;
    size_t encoded_length;
    unsigned int index;

    header.common.flags = MELODI_WIRE_F_BROADCAST | MELODI_WIRE_F_FINAL;
    header.common.destination_native_locator =
        MELODI_NATIVE_LOCATOR_BROADCAST;
    header.logical_length = sizeof(payload_bytes);
    header.delivery_mode = MELODI_DELIVERY_UNRELIABLE;
    header.ordering_marker = 0;
    for (index = 0; index < sizeof(signature); index++)
        signature[index] = index;
    assert(melodi_wire_encode_broadcast_data(
               encoded, sizeof(encoded), &header, signature, payload_bytes,
               sizeof(payload_bytes), &encoded_length) == 0);
    assert(encoded_length == sizeof(expected_broadcast));
    assert(memcmp(encoded, expected_broadcast, sizeof(expected_broadcast)) == 0);
    assert(melodi_wire_decode_broadcast_data(
               encoded, encoded_length, &decoded, decoded_signature, &payload,
               &payload_length) == 0);
    assert(payload_length == sizeof(payload_bytes));
    assert(memcmp(payload, payload_bytes, sizeof(payload_bytes)) == 0);
    assert(memcmp(decoded_signature, signature, sizeof(signature)) == 0);
    encoded[12] = 0x11;
    assert(melodi_wire_decode_broadcast_data(
               encoded, encoded_length, &decoded, decoded_signature, &payload,
               &payload_length) == -EPROTO);
}

static void test_claim_classes(void)
{
    struct melodi_wire_hello decoded;
    struct melodi_wire_hello claim = { 0 };
    uint8_t conflict[MELODI_WIRE_HELLO_SIZE];
    uint8_t hello[MELODI_WIRE_HELLO_SIZE];
    unsigned int index;

    claim.common.flags = MELODI_WIRE_F_BROADCAST;
    claim.common.source_native_locator = 0x10203040;
    claim.common.destination_native_locator =
        MELODI_NATIVE_LOCATOR_BROADCAST;
    claim.common.identity_generation = 2;
    claim.common.message_id = 3;
    claim.common.counter = 4;
    claim.node_id.bytes[0] = MELODI_NODE_ID_SCHEME_ED25519;
    claim.collision_round = 7;
    claim.capabilities = 1;
    claim.expiry_seconds = 300;
    for (index = 1; index < sizeof(claim.node_id.bytes); index++)
        claim.node_id.bytes[index] = index;
    for (index = 0; index < sizeof(claim.challenge); index++)
        claim.challenge[index] = index + 32;
    for (index = 0; index < sizeof(claim.signature); index++)
        claim.signature[index] = index + 64;
    assert(melodi_wire_encode_hello(hello, &claim) == 0);
    assert(melodi_wire_encode_conflict(conflict, &claim) == 0);
    assert(hello[1] == MELODI_WIRE_HELLO);
    assert(conflict[1] == MELODI_WIRE_CONFLICT);
    hello[1] = MELODI_WIRE_CONFLICT;
    assert(memcmp(hello, conflict, sizeof(hello)) == 0);
    assert(melodi_wire_decode_conflict(conflict, sizeof(conflict),
                                       &decoded) == 0);
    assert(decoded.collision_round == claim.collision_round);
    assert(memcmp(decoded.node_id.bytes, claim.node_id.bytes,
                  sizeof(claim.node_id.bytes)) == 0);
    assert(melodi_wire_decode_hello(conflict, sizeof(conflict),
                                    &decoded) == -EPROTO);
}

static void test_control(void)
{
    struct melodi_wire_control decoded;
    struct melodi_wire_control control = { 0 };
    uint8_t encoded[MELODI_WIRE_CONTROL_SIZE];
    unsigned int index;

    control.common.flags = MELODI_WIRE_F_BROADCAST;
    control.common.source_native_locator = 0x10203040;
    control.common.destination_native_locator =
        MELODI_NATIVE_LOCATOR_BROADCAST;
    control.common.identity_generation = 2;
    control.common.message_id = 3;
    control.common.counter = 4;
    control.node_id.bytes[0] = MELODI_NODE_ID_SCHEME_ED25519;
    control.collision_round = 7;
    control.opcode = MELODI_CONTROL_PROBE;
    for (index = 1; index < sizeof(control.node_id.bytes); index++)
        control.node_id.bytes[index] = index;
    for (index = 0; index < sizeof(control.data); index++)
        control.data[index] = index + 32;
    for (index = 0; index < sizeof(control.signature); index++)
        control.signature[index] = index + 64;
    assert(melodi_wire_encode_control(encoded, &control) == 0);
    assert(encoded[0] == MELODI_WIRE_VERSION);
    assert(encoded[1] == MELODI_WIRE_CONTROL);
    assert(encoded[4] == 0 && encoded[5] == MELODI_WIRE_CONTROL_SIZE);
    assert(encoded[109] == 0 && encoded[110] == MELODI_CONTROL_PROBE);
    assert(melodi_wire_decode_control(encoded, sizeof(encoded),
                                      &decoded) == 0);
    assert(decoded.collision_round == control.collision_round);
    assert(memcmp(decoded.data, control.data, sizeof(control.data)) == 0);
    encoded[111] = 1;
    assert(melodi_wire_decode_control(encoded, sizeof(encoded),
                                      &decoded) == -EPROTO);
}

int main(void)
{
    const uint8_t payload_bytes[] = { 0xaa, 0xbb, 0xcc };
    const uint8_t *payload;
    struct melodi_wire_data decoded;
    struct melodi_wire_data header = vector_header();
    uint8_t encoded[sizeof(expected)];
    size_t encoded_length;

    assert(melodi_wire_encode_data(encoded, sizeof(encoded), &header,
                                   payload_bytes, sizeof(payload_bytes),
                                   &encoded_length) == 0);
    assert(encoded_length == sizeof(expected));
    assert(memcmp(encoded, expected, sizeof(expected)) == 0);
    assert(melodi_wire_decode_data(encoded, encoded_length, &decoded,
                                   &payload) == 0);
    assert(decoded.common.message_id == header.common.message_id);
    assert(decoded.destination_service == header.destination_service);
    assert(memcmp(payload, payload_bytes, sizeof(payload_bytes)) == 0);
    encoded[38] = 1;
    assert(melodi_wire_decode_data(encoded, encoded_length, &decoded,
                                   &payload) == -EPROTO);
    encoded[38] = 0;
    encoded[55] = 1;
    assert(melodi_wire_decode_data(encoded, encoded_length, &decoded,
                                   &payload) == -EPROTO);
    test_ack();
    test_broadcast();
    test_claim_classes();
    test_control();
    return 0;
}
