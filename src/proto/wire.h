/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MELODI_WIRE_H
#define MELODI_WIRE_H

#include "mapping.h"

#ifdef __KERNEL__
#include <linux/types.h>
typedef u8 melodi_wire_u8;
typedef u16 melodi_wire_u16;
typedef u32 melodi_wire_u32;
typedef u64 melodi_wire_u64;
#else
#include <stddef.h>
#include <stdint.h>
typedef uint8_t melodi_wire_u8;
typedef uint16_t melodi_wire_u16;
typedef uint32_t melodi_wire_u32;
typedef uint64_t melodi_wire_u64;
#endif

#define MELODI_WIRE_VERSION 1
#define MELODI_WIRE_COMMON_SIZE 40
#define MELODI_WIRE_DATA_SIZE 80
#define MELODI_WIRE_BROADCAST_AUTH_SIZE 60
#define MELODI_WIRE_BROADCAST_SIGNATURE_SUFFIX_SIZE 48
#define MELODI_WIRE_BROADCAST_OVERHEAD \
    MELODI_WIRE_BROADCAST_SIGNATURE_SUFFIX_SIZE
#define MELODI_WIRE_ACK_SIZE 72
#define MELODI_WIRE_ACK_AUTH_SIZE 56
#define MELODI_WIRE_TAG_SIZE 16
#define MELODI_WIRE_SIGNATURE_SIZE 64
#define MELODI_WIRE_CHALLENGE_SIZE 32
#define MELODI_WIRE_HELLO_SIGNED_SIZE 149
#define MELODI_WIRE_HELLO_SIZE 213
#define MELODI_WIRE_AUTH_SIGNED_SIZE 238
#define MELODI_WIRE_AUTH_SIZE 302
#define MELODI_WIRE_CONTROL_DATA_SIZE 32
#define MELODI_WIRE_CONTROL_SIGNED_SIZE 145
#define MELODI_WIRE_CONTROL_SIZE 209
#ifndef MELODI_PRIORITY_MAX
#define MELODI_PRIORITY_MAX 3
#endif

enum melodi_wire_class {
    MELODI_WIRE_HELLO = 1,
    MELODI_WIRE_CHALLENGE,
    MELODI_WIRE_RESPONSE,
    MELODI_WIRE_DATA,
    MELODI_WIRE_ACK,
    MELODI_WIRE_CONFLICT,
    MELODI_WIRE_CONTROL,
};

enum melodi_wire_flag {
    MELODI_WIRE_F_BROADCAST = 1U << 0,
    MELODI_WIRE_F_ENCRYPTED = 1U << 1,
    MELODI_WIRE_F_RELIABLE = 1U << 2,
    MELODI_WIRE_F_ORDERED = 1U << 3,
    MELODI_WIRE_F_FINAL = 1U << 4,
    MELODI_WIRE_F_IGNORABLE = 1U << 15,
};

#define MELODI_WIRE_F_ALL (MELODI_WIRE_F_BROADCAST | \
                           MELODI_WIRE_F_ENCRYPTED | \
                           MELODI_WIRE_F_RELIABLE | \
                           MELODI_WIRE_F_ORDERED | \
                           MELODI_WIRE_F_FINAL | \
                           MELODI_WIRE_F_IGNORABLE)

enum melodi_delivery_mode {
    MELODI_DELIVERY_UNRELIABLE,
    MELODI_DELIVERY_RELIABLE,
    MELODI_DELIVERY_RELIABLE_ORDERED,
};

enum melodi_ack_status {
    MELODI_ACK_PARTIAL,
    MELODI_ACK_COMPLETE,
    MELODI_ACK_REJECTED,
};

enum melodi_control_opcode {
    MELODI_CONTROL_PROBE = 1,
};

struct melodi_wire_common {
    melodi_wire_u8 version;
    melodi_wire_u8 frame_class;
    melodi_wire_u16 flags;
    melodi_wire_u16 header_length;
    melodi_wire_u16 payload_length;
    melodi_wire_u32 source_native_locator;
    melodi_wire_u32 destination_native_locator;
    melodi_wire_u32 identity_generation;
    melodi_wire_u64 message_id;
    melodi_wire_u64 counter;
};

struct melodi_wire_data {
    struct melodi_wire_common common;
    melodi_wire_u16 destination_service;
    melodi_wire_u16 source_service;
    melodi_wire_u16 fragment_index;
    melodi_wire_u16 fragment_count;
    melodi_wire_u32 logical_length;
    melodi_wire_u8 delivery_mode;
    melodi_wire_u8 priority;
    melodi_wire_u32 ordering_marker;
    melodi_wire_u8 tag[MELODI_WIRE_TAG_SIZE];
};

struct melodi_wire_ack {
    struct melodi_wire_common common;
    melodi_wire_u32 acknowledged_generation;
    melodi_wire_u16 fragment_count;
    melodi_wire_u8 status;
    melodi_wire_u64 bitmap;
    melodi_wire_u8 tag[MELODI_WIRE_TAG_SIZE];
};

struct melodi_wire_hello {
    struct melodi_wire_common common;
    struct melodi_node_id node_id;
    melodi_wire_u8 mesh_domain[32];
    melodi_wire_u32 collision_round;
    melodi_wire_u32 capabilities;
    melodi_wire_u32 expiry_seconds;
    melodi_wire_u8 challenge[MELODI_WIRE_CHALLENGE_SIZE];
    melodi_wire_u8 signature[MELODI_WIRE_SIGNATURE_SIZE];
};

struct melodi_wire_auth {
    struct melodi_wire_common common;
    struct melodi_node_id source_node_id;
    struct melodi_node_id destination_node_id;
    melodi_wire_u8 ephemeral_key[32];
    melodi_wire_u8 challenge[MELODI_WIRE_CHALLENGE_SIZE];
    melodi_wire_u8 reply_to[MELODI_WIRE_CHALLENGE_SIZE];
    melodi_wire_u8 mesh_domain[32];
    melodi_wire_u32 collision_round;
    melodi_wire_u8 signature[MELODI_WIRE_SIGNATURE_SIZE];
};

struct melodi_wire_control {
    struct melodi_wire_common common;
    struct melodi_node_id node_id;
    melodi_wire_u8 mesh_domain[32];
    melodi_wire_u32 collision_round;
    melodi_wire_u16 opcode;
    melodi_wire_u8 data[MELODI_WIRE_CONTROL_DATA_SIZE];
    melodi_wire_u8 signature[MELODI_WIRE_SIGNATURE_SIZE];
};

int melodi_wire_encode_data(melodi_wire_u8 *output, size_t capacity,
                            const struct melodi_wire_data *header,
                            const void *payload, size_t payload_length,
                            size_t *encoded_length);
int melodi_wire_encode_broadcast_data(
    melodi_wire_u8 *output, size_t capacity,
    const struct melodi_wire_data *header,
    const melodi_wire_u8 signature[MELODI_WIRE_SIGNATURE_SIZE],
    const void *payload, size_t payload_length, size_t *encoded_length);
int melodi_wire_decode_common(const void *input, size_t length,
                              struct melodi_wire_common *header);
int melodi_wire_decode_data(const void *input, size_t length,
                            struct melodi_wire_data *header,
                            const melodi_wire_u8 **payload);
int melodi_wire_decode_broadcast_data(
    const void *input, size_t length, struct melodi_wire_data *header,
    melodi_wire_u8 signature[MELODI_WIRE_SIGNATURE_SIZE],
    const melodi_wire_u8 **payload, size_t *payload_length);
int melodi_wire_encode_ack(
    melodi_wire_u8 output[MELODI_WIRE_ACK_SIZE],
    const struct melodi_wire_ack *header);
int melodi_wire_decode_ack(const void *input, size_t length,
                           struct melodi_wire_ack *header);
int melodi_wire_encode_hello(melodi_wire_u8 output[MELODI_WIRE_HELLO_SIZE],
                             const struct melodi_wire_hello *header);
int melodi_wire_decode_hello(const void *input, size_t length,
                             struct melodi_wire_hello *header);
int melodi_wire_encode_conflict(
    melodi_wire_u8 output[MELODI_WIRE_HELLO_SIZE],
    const struct melodi_wire_hello *header);
int melodi_wire_decode_conflict(const void *input, size_t length,
                                struct melodi_wire_hello *header);
int melodi_wire_encode_auth(melodi_wire_u8 output[MELODI_WIRE_AUTH_SIZE],
                            const struct melodi_wire_auth *header);
int melodi_wire_decode_auth(const void *input, size_t length,
                            struct melodi_wire_auth *header);
int melodi_wire_encode_control(
    melodi_wire_u8 output[MELODI_WIRE_CONTROL_SIZE],
    const struct melodi_wire_control *header);
int melodi_wire_decode_control(const void *input, size_t length,
                               struct melodi_wire_control *header);

#endif
