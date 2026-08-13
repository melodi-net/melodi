/* SPDX-License-Identifier: GPL-2.0-only */
#include "meshtastic.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
void __msan_check_mem_is_initialized(const volatile void *value, size_t size);
#define MELODI_MSAN_CHECK(value, size) \
    __msan_check_mem_is_initialized((value), (size))
#endif
#endif

#ifndef MELODI_MSAN_CHECK
#define MELODI_MSAN_CHECK(value, size) ((void)(value), (void)(size))
#endif

static void test_stream(void)
{
    static const uint8_t message[] = { 1, 2, 3, 4, 5 };
    struct melodi_mesh_stream stream;
    const uint8_t *decoded = NULL;
    uint8_t combined[64] = { 0 };
    uint8_t frame[32];
    size_t decoded_length = 0;
    size_t frame_length;
    size_t split;
    size_t index;
    unsigned int records;
    int result = 0;

    assert(melodi_mesh_stream_encode(message, sizeof(message), frame,
                                     sizeof(frame), &frame_length) == 0);
    MELODI_MSAN_CHECK(frame, frame_length);
    for (split = 0; split <= frame_length; split++) {
        melodi_mesh_stream_init(&stream);
        assert(melodi_mesh_stream_feed(&stream, 0x55, &decoded,
                                       &decoded_length) == 0);
        assert(melodi_mesh_stream_feed(&stream, 0x94, &decoded,
                                       &decoded_length) == 0);
        for (index = 0; index < split; index++)
            result = melodi_mesh_stream_feed(
                &stream, frame[index], &decoded, &decoded_length);
        for (; index < frame_length; index++)
            result = melodi_mesh_stream_feed(
                &stream, frame[index], &decoded, &decoded_length);
        assert(result == 1);
        assert(decoded_length == sizeof(message));
        assert(memcmp(decoded, message, sizeof(message)) == 0);
    }
    memcpy(combined, frame, frame_length);
    memcpy(combined + frame_length, frame, frame_length);
    MELODI_MSAN_CHECK(combined, frame_length * 2);
    melodi_mesh_stream_init(&stream);
    records = 0;
    for (index = 0; index < frame_length * 2; index++) {
        result = melodi_mesh_stream_feed(
            &stream, combined[index], &decoded, &decoded_length);
        records += result == 1;
    }
    assert(records == 2);
    melodi_mesh_stream_init(&stream);
    assert(melodi_mesh_stream_feed(&stream, 0x94, &decoded,
                                   &decoded_length) == 0);
    assert(melodi_mesh_stream_feed(&stream, 0xc3, &decoded,
                                   &decoded_length) == 0);
    assert(melodi_mesh_stream_feed(&stream, 0x02, &decoded,
                                   &decoded_length) == 0);
    assert(melodi_mesh_stream_feed(&stream, 0x01, &decoded,
                                   &decoded_length) == -EMSGSIZE);
}

static void test_malformed_protobuf(void)
{
    static const uint8_t truncated_varint[] = { 0x80 };
    static const uint8_t zero_field[] = { 0x00 };
    static const uint8_t group[] = { 0x83, 0x01 };
    static const uint8_t unsupported_wire[] = { 0x86, 0x01 };
    static const uint8_t truncated_bytes[] = { 0x12, 0x05, 0x01 };
    static const uint8_t duplicate_event[] = {
        0x38, 0xac, 0x9e, 0x04, 0x38, 0xad, 0x9e, 0x04,
    };
    static const uint8_t encrypted_packet[] = {
        0x12, 0x12, 0x0d, 0x01, 0x00, 0x00, 0x00,
        0x15, 0x02, 0x00, 0x00, 0x00, 0x2a, 0x01,
        0x00, 0x35, 0x03, 0x00, 0x00, 0x00,
    };
    uint8_t oversized[MELODI_MESH_STREAM_MAX + 1] = { 0 };
    struct melodi_mesh_event event;

    assert(melodi_mesh_decode_from_radio_event(
               truncated_varint, sizeof(truncated_varint), &event) ==
           -EMSGSIZE);
    assert(melodi_mesh_decode_from_radio_event(
               zero_field, sizeof(zero_field), &event) == -EPROTO);
    assert(melodi_mesh_decode_from_radio_event(
               group, sizeof(group), &event) == -EPROTO);
    assert(melodi_mesh_decode_from_radio_event(
               unsupported_wire, sizeof(unsupported_wire), &event) ==
           -EPROTO);
    assert(melodi_mesh_decode_from_radio_event(
               truncated_bytes, sizeof(truncated_bytes), &event) ==
           -EMSGSIZE);
    assert(melodi_mesh_decode_from_radio_event(
               duplicate_event, sizeof(duplicate_event), &event) ==
           -EPROTO);
    assert(melodi_mesh_decode_from_radio_event(
               encrypted_packet, sizeof(encrypted_packet), &event) ==
           -EKEYREJECTED);
    assert(melodi_mesh_decode_from_radio_event(
               oversized, sizeof(oversized), &event) == -EINVAL);
}

static void test_to_radio(void)
{
    static const uint8_t expected[] = {
        0x0a, 0x1f, 0x0d, 0x44, 0x33, 0x22, 0x11, 0x15,
        0x88, 0x77, 0x66, 0x55, 0x22, 0x08, 0x08, 0x80,
        0x02, 0x12, 0x03, 0xaa, 0xbb, 0xcc, 0x35, 0x04,
        0x03, 0x02, 0x01, 0x48, 0x03, 0x50, 0x01, 0x58,
        0x46,
    };
    const uint8_t payload[] = { 0xaa, 0xbb, 0xcc };
    struct melodi_mesh_packet packet = {
        .from = 0x11223344,
        .to = 0x55667788,
        .id = 0x01020304,
        .hop_limit = 3,
        .priority = 70,
        .want_ack = true,
        .payload = payload,
        .payload_length = sizeof(payload),
    };
    struct melodi_mesh_command command;
    uint8_t encoded[64];
    size_t length;

    assert(melodi_mesh_encode_to_radio(&packet, encoded, sizeof(encoded),
                                       &length) == 0);
    assert(length == sizeof(expected));
    assert(memcmp(encoded, expected, sizeof(expected)) == 0);
    assert(melodi_mesh_decode_to_radio(encoded, length, &command) == 0);
    assert(command.type == MELODI_MESH_COMMAND_PACKET);
    assert(command.packet.to == packet.to);
    assert(command.packet.id == packet.id);
    assert(command.packet.portnum == MELODI_MESH_PRIVATE_PORT);
    assert(command.packet.payload_length == sizeof(payload));
    assert(melodi_mesh_encode_from_radio(&packet, encoded, sizeof(encoded),
                                         &length) == 0);
    assert(melodi_mesh_decode_from_radio(encoded, length,
                                         &command.packet) == 0);
    assert(command.packet.from == packet.from);
}

static void test_control_encoding(void)
{
    static const uint8_t want_config[] = { 0x18, 0xac, 0x9e, 0x04 };
    static const uint8_t want_nodes[] = { 0x18, 0xad, 0x9e, 0x04 };
    static const uint8_t heartbeat[] = { 0x3a, 0x00 };
    uint8_t encoded[16];
    struct melodi_mesh_command command;
    struct melodi_mesh_event event;
    size_t length;

    assert(melodi_mesh_encode_want_config(MELODI_MESH_CONFIG_NONCE,
                                          encoded, sizeof(encoded),
                                          &length) == 0);
    assert(length == sizeof(want_config));
    assert(memcmp(encoded, want_config, sizeof(want_config)) == 0);
    assert(melodi_mesh_decode_to_radio(encoded, length, &command) == 0);
    assert(command.type == MELODI_MESH_COMMAND_CONFIG_REQUEST);
    assert(command.value == MELODI_MESH_CONFIG_NONCE);
    assert(melodi_mesh_encode_want_config(MELODI_MESH_NODES_NONCE,
                                          encoded, sizeof(encoded),
                                          &length) == 0);
    assert(length == sizeof(want_nodes));
    assert(memcmp(encoded, want_nodes, sizeof(want_nodes)) == 0);
    assert(melodi_mesh_encode_heartbeat(0, encoded, sizeof(encoded),
                                        &length) == 0);
    assert(length == sizeof(heartbeat));
    assert(memcmp(encoded, heartbeat, sizeof(heartbeat)) == 0);
    assert(melodi_mesh_decode_to_radio(encoded, length, &command) == 0);
    assert(command.type == MELODI_MESH_COMMAND_HEARTBEAT);
    assert(command.value == 0);
    assert(melodi_mesh_encode_my_info(0x11223344, encoded,
                                      sizeof(encoded), &length) == 0);
    MELODI_MSAN_CHECK(encoded, length);
    assert(melodi_mesh_decode_from_radio_event(encoded, length,
                                               &event) == 0);
    assert(event.type == MELODI_MESH_EVENT_MY_INFO);
    assert(event.value == 0x11223344);
}

static void test_from_radio(void)
{
    static const uint8_t encoded[] = {
        0x12, 0x20, 0x0d, 0x44, 0x33, 0x22, 0x11, 0x15,
        0x88, 0x77, 0x66, 0x55, 0x22, 0x08, 0x08, 0x80,
        0x02, 0x12, 0x03, 0xaa, 0xbb, 0xcc, 0x35, 0x04,
        0x03, 0x02, 0x01, 0x48, 0x02, 0x78, 0x03, 0xa8,
        0x01, 0x01,
    };
    struct melodi_mesh_packet packet;

    assert(melodi_mesh_decode_from_radio(encoded, sizeof(encoded),
                                         &packet) == 0);
    assert(packet.from == 0x11223344);
    assert(packet.to == 0x55667788);
    assert(packet.id == 0x01020304);
    assert(packet.hop_limit == 2);
    assert(packet.hop_start == 3);
    assert(packet.transport == 1);
    assert(packet.portnum == MELODI_MESH_PRIVATE_PORT);
    assert(packet.payload_length == 3);
    assert(memcmp(packet.payload, "\xaa\xbb\xcc", 3) == 0);
}

static void test_configuration_events(void)
{
    static const uint8_t my_info[] = { 0x1a, 0x02, 0x08, 0x2a };
    static const uint8_t lora[] = {
        0x2a, 0x11, 0x32, 0x0f, 0x08, 0x01, 0x10, 0x03,
        0x38, 0x03, 0x40, 0x03, 0x48, 0x01, 0x58, 0x07,
        0xc0, 0x06, 0x01,
    };
    static const uint8_t long_fast[] = {
        0x2a, 0x0f, 0x32, 0x0d, 0x08, 0x01, 0x38, 0x03,
        0x40, 0x03, 0x48, 0x01, 0x58, 0x07, 0xc0, 0x06,
        0x01,
    };
    static const uint8_t duty_override[] = {
        0x2a, 0x13, 0x32, 0x11, 0x08, 0x01, 0x10, 0x03,
        0x38, 0x03, 0x40, 0x03, 0x48, 0x01, 0x58, 0x07,
        0x60, 0x01, 0xc0, 0x06, 0x01,
    };
    static const uint8_t mqtt[] = { 0x4a, 0x02, 0x0a, 0x00 };
    static const uint8_t channel[] = {
        0x52, 0x04, 0x12, 0x00, 0x18, 0x01,
    };
    static const uint8_t queue[] = {
        0x5a, 0x06, 0x10, 0x02, 0x18, 0x03, 0x20, 0x2a,
    };
    static const uint8_t metadata[] = {
        0x6a, 0x17, 0x0a, 0x11, 'm', 'e', 'l', 'o', 'd', 'i',
        '-', 'u', 's', 'b', '-', 't', 'e', 's', 't', '-', '1',
        0x10, 0x01, 0x48, 0x01,
    };
    static const uint8_t complete[] = { 0x38, 0xac, 0x9e, 0x04 };
    static const uint8_t reset[] = { 0x40, 0x01 };
    struct melodi_mesh_event event;

    assert(melodi_mesh_decode_from_radio_event(my_info, sizeof(my_info),
                                               &event) == 0);
    assert(event.type == MELODI_MESH_EVENT_MY_INFO);
    assert(event.value == 42);
    assert(melodi_mesh_decode_from_radio_event(lora, sizeof(lora),
                                               &event) == 0);
    assert(event.type == MELODI_MESH_EVENT_LORA_CONFIG);
    assert(event.lora.use_preset);
    assert(event.lora.modem_preset == 3);
    assert(event.lora.region == 3);
    assert(event.lora.hop_limit == 3);
    assert(event.lora.tx_enabled);
    assert(event.lora.channel_num == 7);
    assert(event.lora.ignore_mqtt);
    assert(!event.lora.override_duty_cycle);
    assert(melodi_mesh_decode_from_radio_event(long_fast,
                                               sizeof(long_fast),
                                               &event) == 0);
    assert(event.lora.modem_preset == 0);
    assert(melodi_mesh_decode_from_radio_event(duty_override,
                                               sizeof(duty_override),
                                               &event) == 0);
    assert(event.lora.override_duty_cycle);
    assert(melodi_mesh_decode_from_radio_event(mqtt, sizeof(mqtt),
                                               &event) == 0);
    assert(event.type == MELODI_MESH_EVENT_MQTT_CONFIG);
    assert(!event.enabled);
    assert(melodi_mesh_decode_from_radio_event(channel, sizeof(channel),
                                               &event) == 0);
    assert(event.type == MELODI_MESH_EVENT_CHANNEL);
    assert(event.channel.index == 0);
    assert(event.channel.role == 1);
    assert(event.channel.has_settings);
    assert(!event.channel.uplink_enabled);
    assert(!event.channel.downlink_enabled);
    assert(melodi_mesh_decode_from_radio_event(queue, sizeof(queue),
                                               &event) == 0);
    assert(event.type == MELODI_MESH_EVENT_QUEUE_STATUS);
    assert(event.queue.free == 2);
    assert(event.queue.maximum == 3);
    assert(event.queue.packet_id == 42);
    assert(melodi_mesh_decode_from_radio_event(metadata, sizeof(metadata),
                                               &event) == 0);
    assert(event.type == MELODI_MESH_EVENT_METADATA);
    assert(event.metadata.firmware_length == 17);
    assert(memcmp(event.metadata.firmware, "melodi-usb-test-1", 17) == 0);
    assert(event.metadata.device_state_version == 1);
    assert(event.metadata.hardware_model == 1);
    assert(melodi_mesh_decode_from_radio_event(complete, sizeof(complete),
                                               &event) == 0);
    assert(event.type == MELODI_MESH_EVENT_CONFIG_COMPLETE);
    assert(event.value == MELODI_MESH_CONFIG_NONCE);
    assert(melodi_mesh_decode_from_radio_event(reset, sizeof(reset),
                                               &event) == 0);
    assert(event.type == MELODI_MESH_EVENT_RADIO_RESET);
}

static void test_routing_event(void)
{
    static const uint8_t encoded[] = {
        0x12, 0x1c, 0x0d, 0x44, 0x33, 0x22, 0x11, 0x15,
        0x88, 0x77, 0x66, 0x55, 0x22, 0x0b, 0x08, 0x05,
        0x12, 0x02, 0x18, 0x03, 0x35, 0x44, 0x33, 0x22,
        0x11, 0x35, 0x04, 0x03, 0x02, 0x01,
    };
    struct melodi_mesh_event event;
    int32_t result;
    uint32_t request_id;

    assert(melodi_mesh_decode_from_radio_event(encoded, sizeof(encoded),
                                               &event) == 0);
    assert(event.type == MELODI_MESH_EVENT_PACKET);
    assert(event.packet.portnum == MELODI_MESH_ROUTING_PORT);
    assert(melodi_mesh_decode_routing(&event.packet, &result,
                                      &request_id) == 0);
    assert(result == 3);
    assert(request_id == 0x11223344);

    {
        uint8_t response[128];
        size_t length;

        assert(melodi_mesh_encode_routing_response(
                   0x55667788, 0x01020304, 0xaabbccdd, 0x11223344, 3,
                   response, sizeof(response), &length) == 0);
        assert(melodi_mesh_decode_from_radio_event(response, length,
                                                   &event) == 0);
        assert(melodi_mesh_decode_routing(&event.packet, &result,
                                          &request_id) == 0);
        assert(result == 3);
        assert(request_id == 0x11223344);
    }
}

static void test_field_limit(void)
{
    struct melodi_mesh_event event;
    uint8_t encoded[195];
    size_t index;

    for (index = 0; index < sizeof(encoded); index += 3) {
        encoded[index] = 0xa0;
        encoded[index + 1] = 0x01;
        encoded[index + 2] = 0x00;
    }
    assert(melodi_mesh_decode_from_radio_event(encoded, sizeof(encoded),
                                               &event) == -E2BIG);
}

static void test_field_127_is_unknown(void)
{
    static const uint8_t lone[] = { 0xfa, 0x07, 0x01, 0x00 };
    static const uint8_t before_my_info[] = {
        0xfa, 0x07, 0x01, 0x00, 0x1a, 0x02, 0x08, 0x2a,
    };
    static const uint8_t before_config[] = {
        0xfa, 0x07, 0x01, 0x00, 0x18, 0xac, 0x9e, 0x04,
    };
    struct melodi_mesh_command command;
    struct melodi_mesh_event event;

    assert(melodi_mesh_decode_from_radio_event(lone, sizeof(lone),
                                               &event) == -ENOMSG);
    assert(melodi_mesh_decode_to_radio(lone, sizeof(lone),
                                       &command) == -ENOMSG);
    assert(melodi_mesh_decode_from_radio_event(before_my_info,
                                               sizeof(before_my_info),
                                               &event) == 0);
    assert(event.type == MELODI_MESH_EVENT_MY_INFO);
    assert(event.value == 42);
    assert(melodi_mesh_decode_to_radio(before_config, sizeof(before_config),
                                       &command) == 0);
    assert(command.type == MELODI_MESH_COMMAND_CONFIG_REQUEST);
}

static void test_segment(void)
{
    uint8_t payload[3] = { 9, 8, 7 };
    struct melodi_mesh_segment decoded;
    struct melodi_mesh_segment segment = {
        .frame_id = 0x01020304,
        .total_length = MELODI_MESH_FRAME_MTU + sizeof(payload),
        .index = 1,
        .count = 2,
        .payload = payload,
        .payload_length = sizeof(payload),
    };
    uint8_t encoded[MELODI_MESH_DATA_MAX];
    size_t length;

    assert(melodi_mesh_segment_encode(&segment, encoded, sizeof(encoded),
                                      &length) == 0);
    assert(melodi_mesh_segment_decode(encoded, length, &decoded) == 0);
    assert(decoded.frame_id == segment.frame_id);
    assert(decoded.total_length == segment.total_length);
    assert(decoded.index == segment.index);
    assert(decoded.count == segment.count);
    assert(decoded.payload_length == sizeof(payload));
    assert(memcmp(decoded.payload, payload, sizeof(payload)) == 0);
    encoded[3] = 1;
    assert(melodi_mesh_segment_decode(encoded, length, &decoded) == -EPROTO);
    encoded[3] = 0;
    encoded[12] = 0;
    encoded[13] = 0;
    assert(melodi_mesh_segment_decode(encoded, length, &decoded) == -EPROTO);
    encoded[13] = 2;
    encoded[10] = 0;
    encoded[11] = 2;
    assert(melodi_mesh_segment_decode(encoded, length, &decoded) == -EPROTO);
    encoded[11] = 1;
    encoded[14] = 0;
    encoded[15] = 4;
    assert(melodi_mesh_segment_decode(encoded, length, &decoded) == -EPROTO);
}

static void test_airtime(void)
{
    uint64_t airtime_us;
    uint16_t permille;

    assert(melodi_mesh_region_duty_permille(3, &permille) == 0);
    assert(permille == 100);
    assert(melodi_mesh_region_duty_permille(29, &permille) == 0);
    assert(permille == 25);
    assert(melodi_mesh_region_duty_permille(1, &permille) == 0);
    assert(permille == 1000);
    assert(melodi_mesh_region_duty_permille(0, &permille) ==
           -EOPNOTSUPP);
    assert(melodi_mesh_region_duty_permille(30, &permille) ==
           -EOPNOTSUPP);
    assert(melodi_mesh_airtime_estimate(3, false, 1, &airtime_us) == 0);
    assert(airtime_us == 1180672);
    assert(melodi_mesh_airtime_estimate(3, false,
                                        MELODI_MESH_FRAME_MTU + 1,
                                        &airtime_us) == 0);
    assert(airtime_us == 2361344);
    assert(melodi_mesh_airtime_estimate(0, false, 1, &airtime_us) == 0);
    assert(airtime_us == 2156544);
    assert(melodi_mesh_airtime_estimate(2, false, 1, &airtime_us) ==
           -EOPNOTSUPP);
    assert(melodi_mesh_airtime_estimate(3, false, 0, &airtime_us) ==
           -EINVAL);
}

int main(void)
{
    test_stream();
    test_malformed_protobuf();
    test_to_radio();
    test_control_encoding();
    test_from_radio();
    test_configuration_events();
    test_routing_event();
    test_field_limit();
    test_field_127_is_unknown();
    test_segment();
    test_airtime();
    return 0;
}
