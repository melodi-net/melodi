/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <errno.h>
#include <string.h>

#include "radio.h"

static size_t feed_all(struct melodi_radio_stream *stream,
                       const uint8_t *data, size_t length,
                       const struct melodi_radio_header **header,
                       const uint8_t **payload, int *status)
{
    size_t index;

    for (index = 0; index < length; index++) {
        *status = melodi_radio_stream_feed(stream, data[index], header,
                                           payload);
        if (*status)
            return index + 1;
    }
    *status = 0;
    return length;
}

static void test_stream_roundtrip(void)
{
    struct melodi_radio_stream stream;
    const struct melodi_radio_header *header = NULL;
    const uint8_t *payload = NULL;
    uint8_t encoded[64];
    uint8_t body[] = { 1, 2, 3, 4, 5 };
    size_t length;
    size_t consumed;
    int status = 0;

    assert(melodi_radio_stream_encode(MELODI_RADIO_T_STATUS, body,
                                      sizeof(body), encoded, sizeof(encoded),
                                      &length) == 0);
    assert(length == MELODI_RADIO_HEADER_SIZE + sizeof(body));
    assert(encoded[0] == MELODI_RADIO_MAGIC0);
    assert(encoded[1] == MELODI_RADIO_MAGIC1);
    assert(encoded[2] == MELODI_RADIO_VERSION);
    assert(encoded[3] == MELODI_RADIO_T_STATUS);

    melodi_radio_stream_init(&stream);
    consumed = feed_all(&stream, encoded, length, &header, &payload, &status);
    assert(consumed == length);
    assert(status == 1);
    assert(header->type == MELODI_RADIO_T_STATUS);
    assert(header->length == sizeof(body));
    assert(!memcmp(payload, body, sizeof(body)));
}

static void test_stream_resync(void)
{
    struct melodi_radio_stream stream;
    const struct melodi_radio_header *header = NULL;
    const uint8_t *payload = NULL;
    uint8_t noise[] = { 0x00, 0x4d, 0x99, 0x4d, 0x4c, 0x02 };
    uint8_t encoded[64];
    size_t length;
    size_t consumed;
    int status = 0;
    size_t index;

    assert(melodi_radio_encode_identify(encoded, sizeof(encoded),
                                        &length) == 0);
    melodi_radio_stream_init(&stream);
    for (index = 0; index < sizeof(noise); index++)
        melodi_radio_stream_feed(&stream, noise[index], &header, &payload);
    melodi_radio_stream_init(&stream);
    consumed = feed_all(&stream, encoded, length, &header, &payload, &status);
    assert(consumed == length);
    assert(status == 1);
    assert(header->type == MELODI_RADIO_T_IDENTIFY);
    assert(header->length == 0);
}

static void test_stream_checksum(void)
{
    struct melodi_radio_stream stream;
    const struct melodi_radio_header *header = NULL;
    const uint8_t *payload = NULL;
    uint8_t encoded[64];
    uint8_t body[] = { 9, 8, 7 };
    size_t length;
    int status = 0;

    assert(melodi_radio_stream_encode(MELODI_RADIO_T_RESULT, body,
                                      sizeof(body), encoded, sizeof(encoded),
                                      &length) == 0);
    encoded[MELODI_RADIO_HEADER_SIZE] ^= 0xff;
    melodi_radio_stream_init(&stream);
    feed_all(&stream, encoded, length, &header, &payload, &status);
    assert(status == -EBADMSG);
}

static void test_configure(void)
{
    struct melodi_radio_configure config = {
        .locator = 0x11223344,
        .frequency_hz = 868100000,
        .bandwidth_khz = 125,
        .spreading_factor = 11,
        .coding_rate = 5,
        .transmit_power_dbm = 14,
        .duty_permille = 100,
    };
    struct melodi_radio_configure decoded;
    uint8_t encoded[128];
    size_t length;

    memset(config.domain, 0xa5, sizeof(config.domain));
    assert(melodi_radio_encode_configure(&config, encoded, sizeof(encoded),
                                         &length) == 0);
    assert(melodi_radio_decode_configure(encoded + MELODI_RADIO_HEADER_SIZE,
                                         length - MELODI_RADIO_HEADER_SIZE,
                                         &decoded) == 0);
    assert(decoded.locator == config.locator);
    assert(decoded.frequency_hz == config.frequency_hz);
    assert(decoded.bandwidth_khz == config.bandwidth_khz);
    assert(decoded.spreading_factor == config.spreading_factor);
    assert(decoded.coding_rate == config.coding_rate);
    assert(decoded.transmit_power_dbm == config.transmit_power_dbm);
    assert(decoded.duty_permille == config.duty_permille);
    assert(!memcmp(decoded.domain, config.domain, sizeof(config.domain)));

    config.spreading_factor = 13;
    assert(melodi_radio_encode_configure(&config, encoded, sizeof(encoded),
                                         &length) == -EINVAL);
    config.spreading_factor = 11;
    config.locator = MELODI_RADIO_LOCATOR_BROADCAST;
    assert(melodi_radio_encode_configure(&config, encoded, sizeof(encoded),
                                         &length) == -EINVAL);
}

static void test_info_status(void)
{
    struct melodi_radio_info info = {
        .abi_version = 1,
        .packet_mtu = 200,
        .queue_depth = 8,
        .firmware = "melodi-fw-0.1.0",
        .hardware = "feather-rp2040-rfm",
    };
    struct melodi_radio_info decoded_info;
    struct melodi_radio_status status = {
        .locator = 0x55667788,
        .queue_free = 6,
        .queue_depth = 8,
        .state = MELODI_RADIO_STATE_READY,
        .fault = MELODI_RADIO_FAULT_NONE,
    };
    struct melodi_radio_status decoded_status;
    uint8_t encoded[128];
    size_t length;

    assert(melodi_radio_encode_info(&info, encoded, sizeof(encoded),
                                    &length) == 0);
    assert(melodi_radio_decode_info(encoded + MELODI_RADIO_HEADER_SIZE,
                                    length - MELODI_RADIO_HEADER_SIZE,
                                    &decoded_info) == 0);
    assert(decoded_info.packet_mtu == 200);
    assert(decoded_info.queue_depth == 8);
    assert(!strcmp(decoded_info.firmware, "melodi-fw-0.1.0"));
    assert(!strcmp(decoded_info.hardware, "feather-rp2040-rfm"));

    assert(melodi_radio_encode_status(&status, encoded, sizeof(encoded),
                                      &length) == 0);
    assert(melodi_radio_decode_status(encoded + MELODI_RADIO_HEADER_SIZE,
                                      length - MELODI_RADIO_HEADER_SIZE,
                                      &decoded_status) == 0);
    assert(decoded_status.locator == 0x55667788);
    assert(decoded_status.state == MELODI_RADIO_STATE_READY);
    assert(decoded_status.queue_free == 6);

    status.queue_free = 9;
    assert(melodi_radio_encode_status(&status, encoded, sizeof(encoded),
                                      &length) == -EINVAL);
}

static void test_transmit_receive(void)
{
    uint8_t body[64];
    struct melodi_radio_transmit transmit = {
        .cookie = 0xdeadbeef,
        .destination = MELODI_RADIO_LOCATOR_BROADCAST,
        .payload = body,
        .payload_length = sizeof(body),
    };
    struct melodi_radio_transmit decoded_transmit;
    struct melodi_radio_receive receive = {
        .source = 0x01020304,
        .destination = MELODI_RADIO_LOCATOR_BROADCAST,
        .rssi = -113,
        .snr = -7,
        .hops = 2,
        .payload = body,
        .payload_length = sizeof(body),
    };
    struct melodi_radio_receive decoded_receive;
    uint8_t encoded[512];
    size_t length;

    memset(body, 0x5a, sizeof(body));
    assert(melodi_radio_encode_transmit(&transmit, encoded, sizeof(encoded),
                                        &length) == 0);
    assert(melodi_radio_decode_transmit(encoded + MELODI_RADIO_HEADER_SIZE,
                                        length - MELODI_RADIO_HEADER_SIZE,
                                        &decoded_transmit) == 0);
    assert(decoded_transmit.cookie == 0xdeadbeef);
    assert(decoded_transmit.destination == MELODI_RADIO_LOCATOR_BROADCAST);
    assert(decoded_transmit.payload_length == sizeof(body));
    assert(!memcmp(decoded_transmit.payload, body, sizeof(body)));

    assert(melodi_radio_encode_receive(&receive, encoded, sizeof(encoded),
                                       &length) == 0);
    assert(melodi_radio_decode_receive(encoded + MELODI_RADIO_HEADER_SIZE,
                                       length - MELODI_RADIO_HEADER_SIZE,
                                       &decoded_receive) == 0);
    assert(decoded_receive.source == 0x01020304);
    assert(decoded_receive.rssi == -113);
    assert(decoded_receive.snr == -7);
    assert(decoded_receive.hops == 2);
    assert(!memcmp(decoded_receive.payload, body, sizeof(body)));
}

static void test_segment(void)
{
    uint8_t body[100];
    uint8_t encoded[MELODI_RADIO_PACKET_MAX];
    struct melodi_radio_segment segment = {
        .frame_id = 0x0a0b0c0d,
        .total_length = 300,
        .index = 1,
        .count = 3,
        .payload = body,
        .payload_length = sizeof(body),
    };
    struct melodi_radio_segment decoded;
    size_t length;

    memset(body, 0x3c, sizeof(body));
    assert(melodi_radio_segment_encode(&segment, encoded, sizeof(encoded),
                                       &length) == 0);
    assert(length == MELODI_RADIO_SEGMENT_SIZE + sizeof(body));
    assert(melodi_radio_segment_decode(encoded, length, &decoded) == 0);
    assert(decoded.frame_id == segment.frame_id);
    assert(decoded.total_length == 300);
    assert(decoded.index == 1);
    assert(decoded.count == 3);
    assert(decoded.payload_length == sizeof(body));
    assert(!memcmp(decoded.payload, body, sizeof(body)));

    segment.index = 3;
    assert(melodi_radio_segment_encode(&segment, encoded, sizeof(encoded),
                                       &length) == -EINVAL);
}

static void test_airtime(void)
{
    uint32_t fast = 0;
    uint32_t slow = 0;
    uint32_t small = 0;

    assert(melodi_radio_airtime_estimate(7, 125, 5, 200, &fast) == 0);
    assert(melodi_radio_airtime_estimate(12, 125, 5, 200, &slow) == 0);
    assert(melodi_radio_airtime_estimate(7, 125, 5, 20, &small) == 0);
    assert(slow > fast);
    assert(fast > small);
    assert(fast > 100000 && fast < 500000);
    assert(melodi_radio_airtime_estimate(5, 125, 5, 20, &fast) == -EINVAL);
    assert(melodi_radio_airtime_estimate(7, 0, 5, 20, &fast) == -EINVAL);
    assert(melodi_radio_airtime_estimate(7, 125, 9, 20, &fast) == -EINVAL);
}

int main(void)
{
    test_airtime();
    test_stream_roundtrip();
    test_stream_resync();
    test_stream_checksum();
    test_configure();
    test_info_status();
    test_transmit_receive();
    test_segment();
    return 0;
}
