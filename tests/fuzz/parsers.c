/* SPDX-License-Identifier: GPL-2.0-only */
#include "genl.h"
#include "radio.h"
#include "wire.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct melodi_radio_configure config;
    struct melodi_radio_transmit transmit;
    struct melodi_radio_receive receive;
    struct melodi_radio_segment segment;
    struct melodi_radio_stream stream;
    struct melodi_genl_message netlink;
    struct melodi_wire_common common;
    struct melodi_wire_data wire_data;
    struct melodi_wire_ack ack;
    struct melodi_wire_hello hello;
    struct melodi_wire_auth auth;
    uint8_t signature[MELODI_WIRE_SIGNATURE_SIZE];
    const uint8_t *payload;
    const struct melodi_radio_header *header;
    const uint8_t *payload_msg;

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
    struct melodi_radio_status status;
    struct melodi_radio_info info;
    struct melodi_radio_result_report report;

    melodi_radio_decode_configure(data, size, &config);
    melodi_radio_decode_transmit(data, size, &transmit);
    melodi_radio_decode_receive(data, size, &receive);
    melodi_radio_decode_status(data, size, &status);
    melodi_radio_decode_info(data, size, &info);
    melodi_radio_decode_result(data, size, &report);
    melodi_radio_segment_decode(data, size, &segment);
    melodi_radio_stream_init(&stream);
    for (index = 0; index < size; index++)
        melodi_radio_stream_feed(&stream, data[index], &header,
                                 &payload_msg);
    return 0;
}
