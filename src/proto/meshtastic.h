/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MELODI_MESHTASTIC_H
#define MELODI_MESHTASTIC_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef u8 melodi_mesh_u8;
typedef u16 melodi_mesh_u16;
typedef u32 melodi_mesh_u32;
typedef u64 melodi_mesh_u64;
typedef s32 melodi_mesh_s32;
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef uint8_t melodi_mesh_u8;
typedef uint16_t melodi_mesh_u16;
typedef uint32_t melodi_mesh_u32;
typedef uint64_t melodi_mesh_u64;
typedef int32_t melodi_mesh_s32;
#endif

#define MELODI_MESH_STREAM_START1 0x94
#define MELODI_MESH_STREAM_START2 0xc3
#define MELODI_MESH_STREAM_MAX 512
#define MELODI_MESH_DATA_MAX 233
#define MELODI_MESH_PRIVATE_PORT 256
#define MELODI_MESH_ROUTING_PORT 5
#define MELODI_MESH_BROADCAST 0xffffffffU
#define MELODI_MESH_CONFIG_NONCE 69420U
#define MELODI_MESH_NODES_NONCE 69421U
#define MELODI_MESH_SEGMENT_SIZE 16
#define MELODI_MESH_FRAME_MTU \
    (MELODI_MESH_DATA_MAX - MELODI_MESH_SEGMENT_SIZE)
#define MELODI_MESH_FRAME_MAX 4176
#define MELODI_MESH_SEGMENT_LIMIT 32
#define MELODI_MESH_FIRMWARE_MAX 63

enum melodi_mesh_event_type {
    MELODI_MESH_EVENT_PACKET,
    MELODI_MESH_EVENT_MY_INFO,
    MELODI_MESH_EVENT_LORA_CONFIG,
    MELODI_MESH_EVENT_MQTT_CONFIG,
    MELODI_MESH_EVENT_CHANNEL,
    MELODI_MESH_EVENT_QUEUE_STATUS,
    MELODI_MESH_EVENT_METADATA,
    MELODI_MESH_EVENT_CONFIG_COMPLETE,
    MELODI_MESH_EVENT_RADIO_RESET,
};

enum melodi_mesh_command_type {
    MELODI_MESH_COMMAND_PACKET,
    MELODI_MESH_COMMAND_CONFIG_REQUEST,
    MELODI_MESH_COMMAND_HEARTBEAT,
    MELODI_MESH_COMMAND_DISCONNECT,
};

enum melodi_mesh_stream_state {
    MELODI_MESH_SCAN_START1,
    MELODI_MESH_EXPECT_START2,
    MELODI_MESH_READ_LENGTH_HIGH,
    MELODI_MESH_READ_LENGTH_LOW,
    MELODI_MESH_READ_PAYLOAD,
};

struct melodi_mesh_stream {
    enum melodi_mesh_stream_state state;
    melodi_mesh_u16 expected;
    melodi_mesh_u16 length;
    melodi_mesh_u8 buffer[MELODI_MESH_STREAM_MAX];
};

struct melodi_mesh_packet {
    melodi_mesh_u32 portnum;
    melodi_mesh_u32 from;
    melodi_mesh_u32 to;
    melodi_mesh_u32 id;
    melodi_mesh_u32 request_id;
    melodi_mesh_u32 reply_id;
    melodi_mesh_u32 snr_bits;
    melodi_mesh_s32 rssi;
    melodi_mesh_u8 hop_limit;
    melodi_mesh_u8 hop_start;
    melodi_mesh_u8 priority;
    melodi_mesh_u8 transport;
    bool want_ack;
    bool want_response;
    bool via_mqtt;
    const melodi_mesh_u8 *payload;
    size_t payload_length;
};

struct melodi_mesh_lora_config {
    melodi_mesh_u32 modem_preset;
    melodi_mesh_u32 region;
    melodi_mesh_u32 hop_limit;
    melodi_mesh_u32 channel_num;
    bool use_preset;
    bool tx_enabled;
    bool ignore_mqtt;
    bool override_duty_cycle;
};

struct melodi_mesh_channel {
    melodi_mesh_s32 index;
    melodi_mesh_u32 role;
    bool has_settings;
    bool uplink_enabled;
    bool downlink_enabled;
};

struct melodi_mesh_queue_status {
    melodi_mesh_s32 result;
    melodi_mesh_u32 free;
    melodi_mesh_u32 maximum;
    melodi_mesh_u32 packet_id;
};

struct melodi_mesh_metadata {
    const melodi_mesh_u8 *firmware;
    size_t firmware_length;
    melodi_mesh_u32 device_state_version;
    melodi_mesh_u32 role;
    melodi_mesh_u32 hardware_model;
};

struct melodi_mesh_event {
    enum melodi_mesh_event_type type;
    struct melodi_mesh_packet packet;
    struct melodi_mesh_lora_config lora;
    struct melodi_mesh_channel channel;
    struct melodi_mesh_queue_status queue;
    struct melodi_mesh_metadata metadata;
    melodi_mesh_u32 value;
    bool enabled;
};

struct melodi_mesh_command {
    enum melodi_mesh_command_type type;
    struct melodi_mesh_packet packet;
    melodi_mesh_u32 value;
};

struct melodi_mesh_segment {
    melodi_mesh_u32 frame_id;
    melodi_mesh_u16 total_length;
    melodi_mesh_u16 index;
    melodi_mesh_u16 count;
    const melodi_mesh_u8 *payload;
    melodi_mesh_u16 payload_length;
};

void melodi_mesh_stream_init(struct melodi_mesh_stream *stream);
int melodi_mesh_stream_feed(struct melodi_mesh_stream *stream,
                            melodi_mesh_u8 byte,
                            const melodi_mesh_u8 **message, size_t *length);
int melodi_mesh_stream_encode(const void *message, size_t length, void *output,
                              size_t capacity, size_t *encoded_length);
int melodi_mesh_encode_to_radio(const struct melodi_mesh_packet *packet,
                                void *output, size_t capacity,
                                size_t *encoded_length);
int melodi_mesh_encode_from_radio(const struct melodi_mesh_packet *packet,
                                  void *output, size_t capacity,
                                  size_t *encoded_length);
int melodi_mesh_encode_routing_response(
    melodi_mesh_u32 from, melodi_mesh_u32 to, melodi_mesh_u32 packet_id,
    melodi_mesh_u32 request_id, melodi_mesh_s32 result, void *output,
    size_t capacity, size_t *encoded_length);
int melodi_mesh_encode_want_config(melodi_mesh_u32 nonce, void *output,
                                   size_t capacity, size_t *encoded_length);
int melodi_mesh_encode_heartbeat(melodi_mesh_u32 nonce, void *output,
                                 size_t capacity, size_t *encoded_length);
int melodi_mesh_encode_disconnect(void *output, size_t capacity,
                                  size_t *encoded_length);
int melodi_mesh_encode_my_info(melodi_mesh_u32 node_number, void *output,
                               size_t capacity, size_t *encoded_length);
int melodi_mesh_decode_from_radio_event(const void *input, size_t length,
                                        struct melodi_mesh_event *event);
int melodi_mesh_decode_to_radio(const void *input, size_t length,
                                struct melodi_mesh_command *command);
int melodi_mesh_decode_from_radio(const void *input, size_t length,
                                  struct melodi_mesh_packet *packet);
int melodi_mesh_decode_routing(const struct melodi_mesh_packet *packet,
                               melodi_mesh_s32 *result,
                               melodi_mesh_u32 *request_id);
int melodi_mesh_segment_encode(const struct melodi_mesh_segment *segment,
                               void *output, size_t capacity,
                               size_t *encoded_length);
int melodi_mesh_segment_decode(const void *input, size_t length,
                               struct melodi_mesh_segment *segment);
int melodi_mesh_region_duty_permille(melodi_mesh_u32 region,
                                     melodi_mesh_u16 *permille);
int melodi_mesh_airtime_estimate(melodi_mesh_u32 modem_preset,
                                 bool wide_lora, size_t frame_length,
                                 melodi_mesh_u64 *airtime_us);

#endif
