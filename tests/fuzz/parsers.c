/* SPDX-License-Identifier: GPL-2.0-only */
#include "genl.h"
#include "meshtastic.h"
#include "wire.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct melodi_mesh_command command;
    struct melodi_mesh_event event;
    struct melodi_mesh_packet packet;
    struct melodi_mesh_segment segment;
    struct melodi_mesh_stream stream;
    struct melodi_genl_message netlink;
    struct melodi_wire_common common;
    struct melodi_wire_data wire_data;
    struct melodi_wire_ack ack;
    struct melodi_wire_hello hello;
    struct melodi_wire_auth auth;
    uint8_t signature[MELODI_WIRE_SIGNATURE_SIZE];
    const uint8_t *payload;
    const uint8_t *message;
    size_t message_length;
    size_t payload_length;
    size_t index;

    melodi_genl_parse(data, size, &netlink);
    melodi_wire_decode_common(data, size, &common);
    melodi_wire_decode_data(data, size, &wire_data, &payload);
    melodi_wire_decode_broadcast_data(data, size, &wire_data, signature,
                                      &payload, &payload_length);
    melodi_wire_decode_ack(data, size, &ack);
    melodi_wire_decode_hello(data, size, &hello);
    melodi_wire_decode_auth(data, size, &auth);
    melodi_mesh_decode_from_radio_event(data, size, &event);
    melodi_mesh_decode_to_radio(data, size, &command);
    melodi_mesh_decode_from_radio(data, size, &packet);
    melodi_mesh_segment_decode(data, size, &segment);
    melodi_mesh_stream_init(&stream);
    for (index = 0; index < size; index++)
        melodi_mesh_stream_feed(&stream, data[index], &message,
                                &message_length);
    return 0;
}
