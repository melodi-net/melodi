/* SPDX-License-Identifier: GPL-2.0-only */
#include "wire.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

static melodi_wire_u16 melodi_wire_get16(const melodi_wire_u8 *input)
{
    return ((melodi_wire_u16)input[0] << 8) | input[1];
}

static melodi_wire_u32 melodi_wire_get32(const melodi_wire_u8 *input)
{
    return ((melodi_wire_u32)input[0] << 24) |
           ((melodi_wire_u32)input[1] << 16) |
           ((melodi_wire_u32)input[2] << 8) | input[3];
}

static melodi_wire_u64 melodi_wire_get64(const melodi_wire_u8 *input)
{
    return ((melodi_wire_u64)melodi_wire_get32(input) << 32) |
           melodi_wire_get32(input + 4);
}

static void melodi_wire_put16(melodi_wire_u8 *output, melodi_wire_u16 value)
{
    output[0] = value >> 8;
    output[1] = value;
}

static void melodi_wire_put32(melodi_wire_u8 *output, melodi_wire_u32 value)
{
    output[0] = value >> 24;
    output[1] = value >> 16;
    output[2] = value >> 8;
    output[3] = value;
}

static void melodi_wire_put64(melodi_wire_u8 *output, melodi_wire_u64 value)
{
    melodi_wire_put32(output, value >> 32);
    melodi_wire_put32(output + 4, value);
}

static int melodi_wire_class_valid(melodi_wire_u8 frame_class)
{
    return frame_class >= MELODI_WIRE_HELLO &&
           frame_class <= MELODI_WIRE_CONTROL;
}

static void melodi_wire_encode_common(melodi_wire_u8 output[40],
                                      const struct melodi_wire_common *header)
{
    output[0] = header->version;
    output[1] = header->frame_class;
    melodi_wire_put16(output + 2, header->flags);
    melodi_wire_put16(output + 4, header->header_length);
    melodi_wire_put16(output + 6, header->payload_length);
    melodi_wire_put32(output + 8, header->source_native_locator);
    melodi_wire_put32(output + 12, header->destination_native_locator);
    melodi_wire_put32(output + 16, header->identity_generation);
    melodi_wire_put64(output + 20, header->message_id);
    melodi_wire_put64(output + 28, header->counter);
    memset(output + 36, 0, 4);
}

static int melodi_wire_encode_data_header(
    melodi_wire_u8 *output, size_t capacity,
    const struct melodi_wire_data *header, size_t wire_payload_length)
{
    struct melodi_wire_common common;

    if (!output || !header || wire_payload_length > 0xffffU ||
        capacity < MELODI_WIRE_DATA_SIZE + wire_payload_length ||
        header->fragment_count == 0 ||
        header->fragment_index >= header->fragment_count ||
        header->delivery_mode > MELODI_DELIVERY_RELIABLE_ORDERED ||
        header->priority > MELODI_PRIORITY_MAX ||
        header->common.flags & ~MELODI_WIRE_F_ALL)
        return -EINVAL;
    common = header->common;
    common.version = MELODI_WIRE_VERSION;
    common.frame_class = MELODI_WIRE_DATA;
    common.header_length = MELODI_WIRE_DATA_SIZE;
    common.payload_length = wire_payload_length;
    melodi_wire_encode_common(output, &common);
    melodi_wire_put16(output + 40, header->destination_service);
    melodi_wire_put16(output + 42, header->source_service);
    melodi_wire_put16(output + 44, header->fragment_index);
    melodi_wire_put16(output + 46, header->fragment_count);
    melodi_wire_put32(output + 48, header->logical_length);
    output[52] = header->delivery_mode;
    output[53] = header->priority;
    output[54] = 0;
    output[55] = 0;
    melodi_wire_put32(output + 56, header->ordering_marker);
    memcpy(output + 60, header->tag, MELODI_WIRE_TAG_SIZE);
    memset(output + 76, 0, 4);
    return 0;
}

int melodi_wire_encode_data(melodi_wire_u8 *output, size_t capacity,
                            const struct melodi_wire_data *header,
                            const void *payload, size_t payload_length,
                            size_t *encoded_length)
{
    int error;

    if ((!payload && payload_length) || !encoded_length || !header ||
        header->logical_length < payload_length)
        return -EINVAL;
    error = melodi_wire_encode_data_header(output, capacity, header,
                                           payload_length);
    if (error)
        return error;
    if (payload_length)
        memcpy(output + MELODI_WIRE_DATA_SIZE, payload, payload_length);
    *encoded_length = MELODI_WIRE_DATA_SIZE + payload_length;
    return 0;
}

int melodi_wire_encode_broadcast_data(
    melodi_wire_u8 *output, size_t capacity,
    const struct melodi_wire_data *header,
    const melodi_wire_u8 signature[MELODI_WIRE_SIGNATURE_SIZE],
    const void *payload, size_t payload_length, size_t *encoded_length)
{
    struct melodi_wire_data signed_header;
    size_t wire_payload_length;
    int error;

    if (!header || !signature || (!payload && payload_length) ||
        !encoded_length || header->logical_length < payload_length ||
        header->common.destination_native_locator !=
            MELODI_NATIVE_LOCATOR_BROADCAST ||
        (header->common.flags & ~MELODI_WIRE_F_FINAL) !=
            MELODI_WIRE_F_BROADCAST ||
        header->delivery_mode != MELODI_DELIVERY_UNRELIABLE ||
        header->ordering_marker)
        return -EINVAL;
    wire_payload_length = MELODI_WIRE_BROADCAST_OVERHEAD + payload_length;
    signed_header = *header;
    memcpy(signed_header.tag, signature, MELODI_WIRE_TAG_SIZE);
    error = melodi_wire_encode_data_header(output, capacity, &signed_header,
                                           wire_payload_length);
    if (error)
        return error;
    memcpy(output + MELODI_WIRE_DATA_SIZE,
           signature + MELODI_WIRE_TAG_SIZE,
           MELODI_WIRE_BROADCAST_SIGNATURE_SUFFIX_SIZE);
    if (payload_length)
        memcpy(output + MELODI_WIRE_DATA_SIZE +
                   MELODI_WIRE_BROADCAST_OVERHEAD,
               payload, payload_length);
    *encoded_length = MELODI_WIRE_DATA_SIZE + wire_payload_length;
    return 0;
}

int melodi_wire_decode_common(const void *input, size_t length,
                              struct melodi_wire_common *header)
{
    const melodi_wire_u8 *bytes = input;

    if (!input || !header || length < MELODI_WIRE_COMMON_SIZE)
        return -EMSGSIZE;
    header->version = bytes[0];
    header->frame_class = bytes[1];
    header->flags = melodi_wire_get16(bytes + 2);
    header->header_length = melodi_wire_get16(bytes + 4);
    header->payload_length = melodi_wire_get16(bytes + 6);
    header->source_native_locator = melodi_wire_get32(bytes + 8);
    header->destination_native_locator = melodi_wire_get32(bytes + 12);
    header->identity_generation = melodi_wire_get32(bytes + 16);
    header->message_id = melodi_wire_get64(bytes + 20);
    header->counter = melodi_wire_get64(bytes + 28);
    if (header->version != MELODI_WIRE_VERSION ||
        !melodi_wire_class_valid(header->frame_class) ||
        header->flags & ~MELODI_WIRE_F_ALL ||
        header->header_length < MELODI_WIRE_COMMON_SIZE ||
        header->header_length > length ||
        header->payload_length != length - header->header_length ||
        bytes[36] || bytes[37] || bytes[38] || bytes[39])
        return -EPROTO;
    return 0;
}

int melodi_wire_decode_data(const void *input, size_t length,
                            struct melodi_wire_data *header,
                            const melodi_wire_u8 **payload)
{
    const melodi_wire_u8 *bytes = input;
    int error;

    if (!header || !payload)
        return -EINVAL;
    error = melodi_wire_decode_common(input, length, &header->common);
    if (error)
        return error;
    if (header->common.frame_class != MELODI_WIRE_DATA ||
        header->common.header_length != MELODI_WIRE_DATA_SIZE)
        return -EPROTO;
    header->destination_service = melodi_wire_get16(bytes + 40);
    header->source_service = melodi_wire_get16(bytes + 42);
    header->fragment_index = melodi_wire_get16(bytes + 44);
    header->fragment_count = melodi_wire_get16(bytes + 46);
    header->logical_length = melodi_wire_get32(bytes + 48);
    header->delivery_mode = bytes[52];
    header->priority = bytes[53];
    header->ordering_marker = melodi_wire_get32(bytes + 56);
    memcpy(header->tag, bytes + 60, MELODI_WIRE_TAG_SIZE);
    if (header->fragment_count == 0 ||
        header->fragment_index >= header->fragment_count ||
        (header->common.flags & MELODI_WIRE_F_BROADCAST ?
             (header->common.payload_length <
                  MELODI_WIRE_BROADCAST_OVERHEAD ||
              header->logical_length <
                  (melodi_wire_u32)header->common.payload_length -
                      MELODI_WIRE_BROADCAST_OVERHEAD) :
             header->logical_length < header->common.payload_length) ||
        header->delivery_mode > MELODI_DELIVERY_RELIABLE_ORDERED ||
        header->priority > MELODI_PRIORITY_MAX || bytes[54] || bytes[55] ||
        bytes[76] || bytes[77] || bytes[78] || bytes[79])
        return -EPROTO;
    *payload = bytes + MELODI_WIRE_DATA_SIZE;
    return 0;
}

int melodi_wire_decode_broadcast_data(
    const void *input, size_t length, struct melodi_wire_data *header,
    melodi_wire_u8 signature[MELODI_WIRE_SIGNATURE_SIZE],
    const melodi_wire_u8 **payload, size_t *payload_length)
{
    const melodi_wire_u8 *physical_payload;
    int error;

    if (!header || !signature || !payload || !payload_length)
        return -EINVAL;
    error = melodi_wire_decode_data(input, length, header, &physical_payload);
    if (error)
        return error;
    if (header->common.destination_native_locator !=
            MELODI_NATIVE_LOCATOR_BROADCAST ||
        (header->common.flags & ~MELODI_WIRE_F_FINAL) !=
            MELODI_WIRE_F_BROADCAST ||
        header->delivery_mode != MELODI_DELIVERY_UNRELIABLE ||
        header->ordering_marker ||
        header->common.payload_length < MELODI_WIRE_BROADCAST_OVERHEAD)
        return -EPROTO;
    memcpy(signature, header->tag, MELODI_WIRE_TAG_SIZE);
    memcpy(signature + MELODI_WIRE_TAG_SIZE, physical_payload,
           MELODI_WIRE_BROADCAST_SIGNATURE_SUFFIX_SIZE);
    *payload = physical_payload + MELODI_WIRE_BROADCAST_OVERHEAD;
    *payload_length = header->common.payload_length -
                      MELODI_WIRE_BROADCAST_OVERHEAD;
    return 0;
}

int melodi_wire_encode_ack(
    melodi_wire_u8 output[MELODI_WIRE_ACK_SIZE],
    const struct melodi_wire_ack *header)
{
    struct melodi_wire_common common;
    melodi_wire_u64 expected;

    if (!output || !header ||
        header->common.flags != MELODI_WIRE_F_ENCRYPTED ||
        !header->common.source_native_locator ||
        header->common.source_native_locator ==
            MELODI_NATIVE_LOCATOR_BROADCAST ||
        !header->common.destination_native_locator ||
        header->common.destination_native_locator ==
            MELODI_NATIVE_LOCATOR_BROADCAST ||
        !header->common.identity_generation || !header->common.message_id ||
        !header->common.counter || !header->acknowledged_generation ||
        !header->fragment_count || header->fragment_count > 64 ||
        header->status > MELODI_ACK_REJECTED || !header->bitmap)
        return -EINVAL;
    expected = header->fragment_count == 64 ? ~(melodi_wire_u64)0 :
               ((melodi_wire_u64)1 << header->fragment_count) - 1;
    if (header->bitmap & ~expected ||
        (header->status == MELODI_ACK_COMPLETE &&
         header->bitmap != expected))
        return -EINVAL;
    common = header->common;
    common.version = MELODI_WIRE_VERSION;
    common.frame_class = MELODI_WIRE_ACK;
    common.header_length = MELODI_WIRE_ACK_SIZE;
    common.payload_length = 0;
    melodi_wire_encode_common(output, &common);
    melodi_wire_put32(output + 40, header->acknowledged_generation);
    melodi_wire_put16(output + 44, header->fragment_count);
    output[46] = header->status;
    output[47] = 0;
    melodi_wire_put64(output + 48, header->bitmap);
    memcpy(output + MELODI_WIRE_ACK_AUTH_SIZE, header->tag,
           sizeof(header->tag));
    return 0;
}

int melodi_wire_decode_ack(const void *input, size_t length,
                           struct melodi_wire_ack *header)
{
    const melodi_wire_u8 *bytes = input;
    melodi_wire_u64 expected;
    int error;

    if (!header)
        return -EINVAL;
    error = melodi_wire_decode_common(input, length, &header->common);
    if (error)
        return error;
    if (header->common.frame_class != MELODI_WIRE_ACK ||
        header->common.flags != MELODI_WIRE_F_ENCRYPTED ||
        header->common.header_length != MELODI_WIRE_ACK_SIZE ||
        header->common.payload_length ||
        !header->common.source_native_locator ||
        header->common.source_native_locator ==
            MELODI_NATIVE_LOCATOR_BROADCAST ||
        !header->common.destination_native_locator ||
        header->common.destination_native_locator ==
            MELODI_NATIVE_LOCATOR_BROADCAST ||
        !header->common.identity_generation || !header->common.message_id ||
        !header->common.counter || bytes[47])
        return -EPROTO;
    header->acknowledged_generation = melodi_wire_get32(bytes + 40);
    header->fragment_count = melodi_wire_get16(bytes + 44);
    header->status = bytes[46];
    header->bitmap = melodi_wire_get64(bytes + 48);
    memcpy(header->tag, bytes + MELODI_WIRE_ACK_AUTH_SIZE,
           sizeof(header->tag));
    if (!header->acknowledged_generation || !header->fragment_count ||
        header->fragment_count > 64 || header->status > MELODI_ACK_REJECTED ||
        !header->bitmap)
        return -EPROTO;
    expected = header->fragment_count == 64 ? ~(melodi_wire_u64)0 :
               ((melodi_wire_u64)1 << header->fragment_count) - 1;
    if (header->bitmap & ~expected ||
        (header->status == MELODI_ACK_COMPLETE &&
         header->bitmap != expected))
        return -EPROTO;
    return 0;
}

static int melodi_wire_encode_claim(
    melodi_wire_u8 output[MELODI_WIRE_HELLO_SIZE],
    const struct melodi_wire_hello *header, melodi_wire_u8 frame_class)
{
    struct melodi_wire_common common;

    if (!output || !header || header->common.flags & ~MELODI_WIRE_F_BROADCAST ||
        !(header->common.flags & MELODI_WIRE_F_BROADCAST) ||
        header->common.destination_native_locator !=
        MELODI_NATIVE_LOCATOR_BROADCAST ||
        header->node_id.bytes[0] != MELODI_NODE_ID_SCHEME_ED25519)
        return -EINVAL;
    common = header->common;
    common.version = MELODI_WIRE_VERSION;
    common.frame_class = frame_class;
    common.header_length = MELODI_WIRE_HELLO_SIZE;
    common.payload_length = 0;
    melodi_wire_encode_common(output, &common);
    memcpy(output + 40, header->node_id.bytes, MELODI_NODE_ID_SIZE);
    memcpy(output + 73, header->mesh_domain, sizeof(header->mesh_domain));
    melodi_wire_put32(output + 105, header->collision_round);
    melodi_wire_put32(output + 109, header->capabilities);
    melodi_wire_put32(output + 113, header->expiry_seconds);
    memcpy(output + 117, header->challenge, sizeof(header->challenge));
    memcpy(output + MELODI_WIRE_HELLO_SIGNED_SIZE, header->signature,
           sizeof(header->signature));
    return 0;
}

int melodi_wire_encode_hello(melodi_wire_u8 output[MELODI_WIRE_HELLO_SIZE],
                             const struct melodi_wire_hello *header)
{
    return melodi_wire_encode_claim(output, header, MELODI_WIRE_HELLO);
}

int melodi_wire_encode_conflict(
    melodi_wire_u8 output[MELODI_WIRE_HELLO_SIZE],
    const struct melodi_wire_hello *header)
{
    return melodi_wire_encode_claim(output, header, MELODI_WIRE_CONFLICT);
}

static int melodi_wire_decode_claim(const void *input, size_t length,
                                    struct melodi_wire_hello *header,
                                    melodi_wire_u8 frame_class)
{
    const melodi_wire_u8 *bytes = input;
    int error;

    if (!header)
        return -EINVAL;
    error = melodi_wire_decode_common(input, length, &header->common);
    if (error)
        return error;
    if (header->common.frame_class != frame_class ||
        header->common.header_length != MELODI_WIRE_HELLO_SIZE ||
        header->common.payload_length != 0 ||
        header->common.flags != MELODI_WIRE_F_BROADCAST ||
        header->common.destination_native_locator !=
        MELODI_NATIVE_LOCATOR_BROADCAST)
        return -EPROTO;
    memcpy(header->node_id.bytes, bytes + 40, MELODI_NODE_ID_SIZE);
    memcpy(header->mesh_domain, bytes + 73, sizeof(header->mesh_domain));
    header->collision_round = melodi_wire_get32(bytes + 105);
    header->capabilities = melodi_wire_get32(bytes + 109);
    header->expiry_seconds = melodi_wire_get32(bytes + 113);
    memcpy(header->challenge, bytes + 117, sizeof(header->challenge));
    memcpy(header->signature, bytes + MELODI_WIRE_HELLO_SIGNED_SIZE,
           sizeof(header->signature));
    return header->node_id.bytes[0] == MELODI_NODE_ID_SCHEME_ED25519 ?
           0 : -EPROTO;
}

int melodi_wire_decode_hello(const void *input, size_t length,
                             struct melodi_wire_hello *header)
{
    return melodi_wire_decode_claim(input, length, header,
                                    MELODI_WIRE_HELLO);
}

int melodi_wire_decode_conflict(const void *input, size_t length,
                                struct melodi_wire_hello *header)
{
    return melodi_wire_decode_claim(input, length, header,
                                    MELODI_WIRE_CONFLICT);
}

int melodi_wire_encode_auth(melodi_wire_u8 output[MELODI_WIRE_AUTH_SIZE],
                            const struct melodi_wire_auth *header)
{
    struct melodi_wire_common common;

    if (!output || !header ||
        (header->common.frame_class != MELODI_WIRE_CHALLENGE &&
         header->common.frame_class != MELODI_WIRE_RESPONSE) ||
        header->common.flags != 0 ||
        header->common.source_native_locator ==
            MELODI_NATIVE_LOCATOR_INVALID ||
        header->common.source_native_locator ==
            MELODI_NATIVE_LOCATOR_BROADCAST ||
        header->common.destination_native_locator ==
            MELODI_NATIVE_LOCATOR_INVALID ||
        header->common.destination_native_locator ==
            MELODI_NATIVE_LOCATOR_BROADCAST ||
        header->source_node_id.bytes[0] !=
        MELODI_NODE_ID_SCHEME_ED25519 ||
        header->destination_node_id.bytes[0] !=
        MELODI_NODE_ID_SCHEME_ED25519)
        return -EINVAL;
    common = header->common;
    common.version = MELODI_WIRE_VERSION;
    common.header_length = MELODI_WIRE_AUTH_SIZE;
    common.payload_length = 0;
    melodi_wire_encode_common(output, &common);
    memcpy(output + 40, header->source_node_id.bytes, MELODI_NODE_ID_SIZE);
    memcpy(output + 73, header->destination_node_id.bytes,
           MELODI_NODE_ID_SIZE);
    memcpy(output + 106, header->ephemeral_key,
           sizeof(header->ephemeral_key));
    memcpy(output + 138, header->challenge, sizeof(header->challenge));
    memcpy(output + 170, header->reply_to, sizeof(header->reply_to));
    memcpy(output + 202, header->mesh_domain, sizeof(header->mesh_domain));
    melodi_wire_put32(output + 234, header->collision_round);
    memcpy(output + MELODI_WIRE_AUTH_SIGNED_SIZE, header->signature,
           sizeof(header->signature));
    return 0;
}

int melodi_wire_decode_auth(const void *input, size_t length,
                            struct melodi_wire_auth *header)
{
    const melodi_wire_u8 *bytes = input;
    int error;

    if (!header)
        return -EINVAL;
    error = melodi_wire_decode_common(input, length, &header->common);
    if (error)
        return error;
    if ((header->common.frame_class != MELODI_WIRE_CHALLENGE &&
         header->common.frame_class != MELODI_WIRE_RESPONSE) ||
        header->common.flags != 0 ||
        header->common.header_length != MELODI_WIRE_AUTH_SIZE ||
        header->common.payload_length != 0 ||
        header->common.source_native_locator ==
            MELODI_NATIVE_LOCATOR_INVALID ||
        header->common.source_native_locator ==
            MELODI_NATIVE_LOCATOR_BROADCAST ||
        header->common.destination_native_locator ==
            MELODI_NATIVE_LOCATOR_INVALID ||
        header->common.destination_native_locator ==
            MELODI_NATIVE_LOCATOR_BROADCAST)
        return -EPROTO;
    memcpy(header->source_node_id.bytes, bytes + 40, MELODI_NODE_ID_SIZE);
    memcpy(header->destination_node_id.bytes, bytes + 73,
           MELODI_NODE_ID_SIZE);
    memcpy(header->ephemeral_key, bytes + 106,
           sizeof(header->ephemeral_key));
    memcpy(header->challenge, bytes + 138, sizeof(header->challenge));
    memcpy(header->reply_to, bytes + 170, sizeof(header->reply_to));
    memcpy(header->mesh_domain, bytes + 202, sizeof(header->mesh_domain));
    header->collision_round = melodi_wire_get32(bytes + 234);
    memcpy(header->signature, bytes + MELODI_WIRE_AUTH_SIGNED_SIZE,
           sizeof(header->signature));
    if (header->source_node_id.bytes[0] !=
        MELODI_NODE_ID_SCHEME_ED25519 ||
        header->destination_node_id.bytes[0] !=
        MELODI_NODE_ID_SCHEME_ED25519)
        return -EPROTO;
    return 0;
}

int melodi_wire_encode_control(
    melodi_wire_u8 output[MELODI_WIRE_CONTROL_SIZE],
    const struct melodi_wire_control *header)
{
    struct melodi_wire_common common;

    if (!output || !header ||
        header->common.flags != MELODI_WIRE_F_BROADCAST ||
        header->common.source_native_locator ==
            MELODI_NATIVE_LOCATOR_INVALID ||
        header->common.source_native_locator ==
            MELODI_NATIVE_LOCATOR_BROADCAST ||
        header->common.destination_native_locator !=
            MELODI_NATIVE_LOCATOR_BROADCAST ||
        header->node_id.bytes[0] != MELODI_NODE_ID_SCHEME_ED25519 ||
        header->opcode != MELODI_CONTROL_PROBE)
        return -EINVAL;
    common = header->common;
    common.version = MELODI_WIRE_VERSION;
    common.frame_class = MELODI_WIRE_CONTROL;
    common.header_length = MELODI_WIRE_CONTROL_SIZE;
    common.payload_length = 0;
    melodi_wire_encode_common(output, &common);
    memcpy(output + 40, header->node_id.bytes, MELODI_NODE_ID_SIZE);
    memcpy(output + 73, header->mesh_domain, sizeof(header->mesh_domain));
    melodi_wire_put32(output + 105, header->collision_round);
    melodi_wire_put16(output + 109, header->opcode);
    output[111] = 0;
    output[112] = 0;
    memcpy(output + 113, header->data, sizeof(header->data));
    memcpy(output + MELODI_WIRE_CONTROL_SIGNED_SIZE, header->signature,
           sizeof(header->signature));
    return 0;
}

int melodi_wire_decode_control(const void *input, size_t length,
                               struct melodi_wire_control *header)
{
    const melodi_wire_u8 *bytes = input;
    int error;

    if (!header)
        return -EINVAL;
    error = melodi_wire_decode_common(input, length, &header->common);
    if (error)
        return error;
    if (header->common.frame_class != MELODI_WIRE_CONTROL ||
        header->common.flags != MELODI_WIRE_F_BROADCAST ||
        header->common.header_length != MELODI_WIRE_CONTROL_SIZE ||
        header->common.payload_length != 0 ||
        header->common.source_native_locator ==
            MELODI_NATIVE_LOCATOR_INVALID ||
        header->common.source_native_locator ==
            MELODI_NATIVE_LOCATOR_BROADCAST ||
        header->common.destination_native_locator !=
            MELODI_NATIVE_LOCATOR_BROADCAST || bytes[111] || bytes[112])
        return -EPROTO;
    memcpy(header->node_id.bytes, bytes + 40, MELODI_NODE_ID_SIZE);
    memcpy(header->mesh_domain, bytes + 73, sizeof(header->mesh_domain));
    header->collision_round = melodi_wire_get32(bytes + 105);
    header->opcode = melodi_wire_get16(bytes + 109);
    memcpy(header->data, bytes + 113, sizeof(header->data));
    memcpy(header->signature, bytes + MELODI_WIRE_CONTROL_SIGNED_SIZE,
           sizeof(header->signature));
    if (header->node_id.bytes[0] != MELODI_NODE_ID_SCHEME_ED25519 ||
        header->opcode != MELODI_CONTROL_PROBE)
        return -EPROTO;
    return 0;
}
