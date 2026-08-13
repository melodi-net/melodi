/* SPDX-License-Identifier: GPL-2.0-only */
#include "radio.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

#define MELODI_RADIO_CONFIGURE_SIZE 48
#define MELODI_RADIO_INFO_SIZE 72
#define MELODI_RADIO_STATUS_SIZE 10
#define MELODI_RADIO_TRANSMIT_SIZE 10
#define MELODI_RADIO_RECEIVE_SIZE 16
#define MELODI_RADIO_RESULT_SIZE 10

static void melodi_radio_put_u16(melodi_radio_u8 *output,
                                 melodi_radio_u16 value)
{
    output[0] = (melodi_radio_u8)(value >> 8);
    output[1] = (melodi_radio_u8)value;
}

static void melodi_radio_put_u32(melodi_radio_u8 *output,
                                 melodi_radio_u32 value)
{
    output[0] = (melodi_radio_u8)(value >> 24);
    output[1] = (melodi_radio_u8)(value >> 16);
    output[2] = (melodi_radio_u8)(value >> 8);
    output[3] = (melodi_radio_u8)value;
}

static melodi_radio_u16 melodi_radio_get_u16(const melodi_radio_u8 *input)
{
    return (melodi_radio_u16)((melodi_radio_u16)input[0] << 8 | input[1]);
}

static melodi_radio_u32 melodi_radio_get_u32(const melodi_radio_u8 *input)
{
    return (melodi_radio_u32)input[0] << 24 |
           (melodi_radio_u32)input[1] << 16 |
           (melodi_radio_u32)input[2] << 8 | input[3];
}

static melodi_radio_u16 melodi_radio_checksum(const melodi_radio_u8 *data,
                                              size_t length)
{
    melodi_radio_u32 sum = 0;
    size_t index;

    for (index = 0; index < length; index++)
        sum += data[index];
    while (sum >> 16)
        sum = (sum & 0xffffU) + (sum >> 16);
    return (melodi_radio_u16)~sum;
}

static void melodi_radio_put_text(melodi_radio_u8 *output, const char *text,
                                  size_t capacity)
{
    size_t index;

    memset(output, 0, capacity);
    if (!text)
        return;
    for (index = 0; index < capacity - 1 && text[index]; index++)
        output[index] = (melodi_radio_u8)text[index];
}

static int melodi_radio_get_text(char *output, const melodi_radio_u8 *input,
                                 size_t capacity)
{
    size_t index;

    for (index = 0; index < capacity - 1; index++) {
        if (!input[index])
            break;
        if (input[index] < 0x20 || input[index] > 0x7e)
            return -EPROTO;
        output[index] = (char)input[index];
    }
    output[index] = 0;
    return 0;
}

void melodi_radio_stream_init(struct melodi_radio_stream *stream)
{
    if (!stream)
        return;
    memset(stream, 0, sizeof(*stream));
    stream->state = MELODI_RADIO_SCAN_MAGIC0;
}

int melodi_radio_stream_encode(melodi_radio_u8 type, const void *payload,
                               size_t length, void *output, size_t capacity,
                               size_t *encoded_length)
{
    melodi_radio_u8 *out = output;

    if (!output || !encoded_length || length > MELODI_RADIO_PAYLOAD_MAX ||
        (!payload && length))
        return -EINVAL;
    if (capacity < MELODI_RADIO_HEADER_SIZE + length)
        return -ENOSPC;
    out[0] = MELODI_RADIO_MAGIC0;
    out[1] = MELODI_RADIO_MAGIC1;
    out[2] = MELODI_RADIO_VERSION;
    out[3] = type;
    melodi_radio_put_u16(out + 4, (melodi_radio_u16)length);
    melodi_radio_put_u16(out + 6, melodi_radio_checksum(payload, length));
    if (length)
        memcpy(out + MELODI_RADIO_HEADER_SIZE, payload, length);
    *encoded_length = MELODI_RADIO_HEADER_SIZE + length;
    return 0;
}

int melodi_radio_stream_feed(struct melodi_radio_stream *stream,
                             melodi_radio_u8 byte,
                             const struct melodi_radio_header **header,
                             const melodi_radio_u8 **payload)
{
    if (!stream || !header || !payload)
        return -EINVAL;
    switch (stream->state) {
    case MELODI_RADIO_SCAN_MAGIC0:
        if (byte == MELODI_RADIO_MAGIC0)
            stream->state = MELODI_RADIO_SCAN_MAGIC1;
        return 0;
    case MELODI_RADIO_SCAN_MAGIC1:
        if (byte == MELODI_RADIO_MAGIC1) {
            stream->state = MELODI_RADIO_READ_HEADER;
            stream->offset = 0;
        } else if (byte != MELODI_RADIO_MAGIC0) {
            stream->state = MELODI_RADIO_SCAN_MAGIC0;
        }
        return 0;
    case MELODI_RADIO_READ_HEADER:
        stream->buffer[stream->offset++] = byte;
        if (stream->offset < MELODI_RADIO_HEADER_SIZE - 2)
            return 0;
        stream->header.magic0 = MELODI_RADIO_MAGIC0;
        stream->header.magic1 = MELODI_RADIO_MAGIC1;
        stream->header.version = stream->buffer[0];
        stream->header.type = stream->buffer[1];
        stream->header.length = melodi_radio_get_u16(stream->buffer + 2);
        stream->header.checksum = melodi_radio_get_u16(stream->buffer + 4);
        stream->offset = 0;
        if (stream->header.version != MELODI_RADIO_VERSION ||
            stream->header.length > MELODI_RADIO_PAYLOAD_MAX) {
            stream->state = MELODI_RADIO_SCAN_MAGIC0;
            return -EPROTO;
        }
        stream->expected = stream->header.length;
        if (!stream->expected) {
            stream->state = MELODI_RADIO_SCAN_MAGIC0;
            if (stream->header.checksum != melodi_radio_checksum(NULL, 0))
                return -EBADMSG;
            *header = &stream->header;
            *payload = stream->buffer;
            return 1;
        }
        stream->state = MELODI_RADIO_READ_PAYLOAD;
        return 0;
    case MELODI_RADIO_READ_PAYLOAD:
        stream->buffer[stream->offset++] = byte;
        if (stream->offset < stream->expected)
            return 0;
        stream->state = MELODI_RADIO_SCAN_MAGIC0;
        if (stream->header.checksum !=
            melodi_radio_checksum(stream->buffer, stream->expected))
            return -EBADMSG;
        *header = &stream->header;
        *payload = stream->buffer;
        return 1;
    }
    stream->state = MELODI_RADIO_SCAN_MAGIC0;
    return -EPROTO;
}

int melodi_radio_encode_identify(void *output, size_t capacity,
                                 size_t *encoded_length)
{
    return melodi_radio_stream_encode(MELODI_RADIO_T_IDENTIFY, NULL, 0,
                                      output, capacity, encoded_length);
}

int melodi_radio_encode_reset(void *output, size_t capacity,
                              size_t *encoded_length)
{
    return melodi_radio_stream_encode(MELODI_RADIO_T_RESET, NULL, 0, output,
                                      capacity, encoded_length);
}

int melodi_radio_encode_configure(const struct melodi_radio_configure *config,
                                  void *output, size_t capacity,
                                  size_t *encoded_length)
{
    melodi_radio_u8 payload[MELODI_RADIO_CONFIGURE_SIZE];

    if (!config || !config->locator ||
        config->locator == MELODI_RADIO_LOCATOR_BROADCAST ||
        !config->frequency_hz || !config->bandwidth_khz ||
        config->spreading_factor < 6 || config->spreading_factor > 12 ||
        config->coding_rate < 5 || config->coding_rate > 8 ||
        !config->duty_permille || config->duty_permille > 1000)
        return -EINVAL;
    memcpy(payload, config->domain, MELODI_RADIO_DOMAIN_SIZE);
    melodi_radio_put_u32(payload + 32, config->locator);
    melodi_radio_put_u32(payload + 36, config->frequency_hz);
    melodi_radio_put_u16(payload + 40, config->bandwidth_khz);
    payload[42] = config->spreading_factor;
    payload[43] = config->coding_rate;
    melodi_radio_put_u16(payload + 44,
                         (melodi_radio_u16)config->transmit_power_dbm);
    melodi_radio_put_u16(payload + 46, config->duty_permille);
    return melodi_radio_stream_encode(MELODI_RADIO_T_CONFIGURE, payload,
                                      sizeof(payload), output, capacity,
                                      encoded_length);
}

int melodi_radio_decode_configure(const void *input, size_t length,
                                  struct melodi_radio_configure *config)
{
    const melodi_radio_u8 *payload = input;

    if (!input || !config || length != MELODI_RADIO_CONFIGURE_SIZE)
        return -EINVAL;
    memset(config, 0, sizeof(*config));
    memcpy(config->domain, payload, MELODI_RADIO_DOMAIN_SIZE);
    config->locator = melodi_radio_get_u32(payload + 32);
    config->frequency_hz = melodi_radio_get_u32(payload + 36);
    config->bandwidth_khz = melodi_radio_get_u16(payload + 40);
    config->spreading_factor = payload[42];
    config->coding_rate = payload[43];
    config->transmit_power_dbm =
        (melodi_radio_s16)melodi_radio_get_u16(payload + 44);
    config->duty_permille = melodi_radio_get_u16(payload + 46);
    if (!config->locator ||
        config->locator == MELODI_RADIO_LOCATOR_BROADCAST ||
        !config->frequency_hz || !config->bandwidth_khz ||
        config->spreading_factor < 6 || config->spreading_factor > 12 ||
        config->coding_rate < 5 || config->coding_rate > 8 ||
        !config->duty_permille || config->duty_permille > 1000)
        return -EPROTO;
    return 0;
}

int melodi_radio_encode_info(const struct melodi_radio_info *info,
                             void *output, size_t capacity,
                             size_t *encoded_length)
{
    melodi_radio_u8 payload[MELODI_RADIO_INFO_SIZE];

    if (!info || !info->packet_mtu ||
        info->packet_mtu > MELODI_RADIO_PACKET_MAX || !info->queue_depth)
        return -EINVAL;
    melodi_radio_put_u32(payload, info->abi_version);
    melodi_radio_put_u16(payload + 4, info->packet_mtu);
    melodi_radio_put_u16(payload + 6, info->queue_depth);
    melodi_radio_put_text(payload + 8, info->firmware, 32);
    melodi_radio_put_text(payload + 40, info->hardware, 32);
    return melodi_radio_stream_encode(MELODI_RADIO_T_INFO, payload,
                                      sizeof(payload), output, capacity,
                                      encoded_length);
}

int melodi_radio_decode_info(const void *input, size_t length,
                             struct melodi_radio_info *info)
{
    const melodi_radio_u8 *payload = input;
    int error;

    if (!input || !info || length != MELODI_RADIO_INFO_SIZE)
        return -EINVAL;
    memset(info, 0, sizeof(*info));
    info->abi_version = melodi_radio_get_u32(payload);
    info->packet_mtu = melodi_radio_get_u16(payload + 4);
    info->queue_depth = melodi_radio_get_u16(payload + 6);
    error = melodi_radio_get_text(info->firmware, payload + 8,
                                  sizeof(info->firmware));
    if (!error)
        error = melodi_radio_get_text(info->hardware, payload + 40,
                                      sizeof(info->hardware));
    if (error)
        return error;
    if (!info->packet_mtu || info->packet_mtu > MELODI_RADIO_PACKET_MAX ||
        !info->queue_depth)
        return -EPROTO;
    return 0;
}

int melodi_radio_encode_status(const struct melodi_radio_status *status,
                               void *output, size_t capacity,
                               size_t *encoded_length)
{
    melodi_radio_u8 payload[MELODI_RADIO_STATUS_SIZE];

    if (!status || status->state > MELODI_RADIO_STATE_FAILED ||
        status->fault > MELODI_RADIO_FAULT_INTERNAL ||
        status->queue_free > status->queue_depth)
        return -EINVAL;
    melodi_radio_put_u32(payload, status->locator);
    melodi_radio_put_u16(payload + 4, status->queue_free);
    melodi_radio_put_u16(payload + 6, status->queue_depth);
    payload[8] = status->state;
    payload[9] = status->fault;
    return melodi_radio_stream_encode(MELODI_RADIO_T_STATUS, payload,
                                      sizeof(payload), output, capacity,
                                      encoded_length);
}

int melodi_radio_decode_status(const void *input, size_t length,
                               struct melodi_radio_status *status)
{
    const melodi_radio_u8 *payload = input;

    if (!input || !status || length != MELODI_RADIO_STATUS_SIZE)
        return -EINVAL;
    memset(status, 0, sizeof(*status));
    status->locator = melodi_radio_get_u32(payload);
    status->queue_free = melodi_radio_get_u16(payload + 4);
    status->queue_depth = melodi_radio_get_u16(payload + 6);
    status->state = payload[8];
    status->fault = payload[9];
    if (status->state > MELODI_RADIO_STATE_FAILED ||
        status->fault > MELODI_RADIO_FAULT_INTERNAL ||
        status->queue_free > status->queue_depth)
        return -EPROTO;
    return 0;
}

int melodi_radio_encode_transmit(const struct melodi_radio_transmit *transmit,
                                 void *output, size_t capacity,
                                 size_t *encoded_length)
{
    melodi_radio_u8 payload[MELODI_RADIO_TRANSMIT_SIZE +
                            MELODI_RADIO_PACKET_MAX];

    if (!transmit || !transmit->cookie || !transmit->destination ||
        !transmit->payload || !transmit->payload_length ||
        transmit->payload_length > MELODI_RADIO_PACKET_MAX)
        return -EINVAL;
    melodi_radio_put_u32(payload, transmit->cookie);
    melodi_radio_put_u32(payload + 4, transmit->destination);
    melodi_radio_put_u16(payload + 8, transmit->payload_length);
    memcpy(payload + MELODI_RADIO_TRANSMIT_SIZE, transmit->payload,
           transmit->payload_length);
    return melodi_radio_stream_encode(
        MELODI_RADIO_T_TRANSMIT, payload,
        MELODI_RADIO_TRANSMIT_SIZE + transmit->payload_length, output,
        capacity, encoded_length);
}

int melodi_radio_decode_transmit(const void *input, size_t length,
                                 struct melodi_radio_transmit *transmit)
{
    const melodi_radio_u8 *payload = input;

    if (!input || !transmit || length < MELODI_RADIO_TRANSMIT_SIZE)
        return -EINVAL;
    memset(transmit, 0, sizeof(*transmit));
    transmit->cookie = melodi_radio_get_u32(payload);
    transmit->destination = melodi_radio_get_u32(payload + 4);
    transmit->payload_length = melodi_radio_get_u16(payload + 8);
    if (!transmit->cookie || !transmit->destination ||
        !transmit->payload_length ||
        transmit->payload_length > MELODI_RADIO_PACKET_MAX ||
        length != (size_t)MELODI_RADIO_TRANSMIT_SIZE +
                      transmit->payload_length)
        return -EPROTO;
    transmit->payload = payload + MELODI_RADIO_TRANSMIT_SIZE;
    return 0;
}

int melodi_radio_encode_receive(const struct melodi_radio_receive *receive,
                                void *output, size_t capacity,
                                size_t *encoded_length)
{
    melodi_radio_u8 payload[MELODI_RADIO_RECEIVE_SIZE +
                            MELODI_RADIO_PACKET_MAX];

    if (!receive || !receive->source || !receive->destination ||
        !receive->payload || !receive->payload_length ||
        receive->payload_length > MELODI_RADIO_PACKET_MAX)
        return -EINVAL;
    melodi_radio_put_u32(payload, receive->source);
    melodi_radio_put_u32(payload + 4, receive->destination);
    melodi_radio_put_u16(payload + 8, (melodi_radio_u16)receive->rssi);
    melodi_radio_put_u16(payload + 10, (melodi_radio_u16)receive->snr);
    payload[12] = receive->hops;
    payload[13] = 0;
    melodi_radio_put_u16(payload + 14, receive->payload_length);
    memcpy(payload + MELODI_RADIO_RECEIVE_SIZE, receive->payload,
           receive->payload_length);
    return melodi_radio_stream_encode(
        MELODI_RADIO_T_RECEIVE, payload,
        MELODI_RADIO_RECEIVE_SIZE + receive->payload_length, output, capacity,
        encoded_length);
}

int melodi_radio_decode_receive(const void *input, size_t length,
                                struct melodi_radio_receive *receive)
{
    const melodi_radio_u8 *payload = input;

    if (!input || !receive || length < MELODI_RADIO_RECEIVE_SIZE)
        return -EINVAL;
    memset(receive, 0, sizeof(*receive));
    receive->source = melodi_radio_get_u32(payload);
    receive->destination = melodi_radio_get_u32(payload + 4);
    receive->rssi = (melodi_radio_s16)melodi_radio_get_u16(payload + 8);
    receive->snr = (melodi_radio_s16)melodi_radio_get_u16(payload + 10);
    receive->hops = payload[12];
    receive->payload_length = melodi_radio_get_u16(payload + 14);
    if (!receive->source || !receive->destination ||
        !receive->payload_length ||
        receive->payload_length > MELODI_RADIO_PACKET_MAX ||
        length != (size_t)MELODI_RADIO_RECEIVE_SIZE +
                      receive->payload_length)
        return -EPROTO;
    receive->payload = payload + MELODI_RADIO_RECEIVE_SIZE;
    return 0;
}

int melodi_radio_encode_result(
    const struct melodi_radio_result_report *report, void *output,
    size_t capacity, size_t *encoded_length)
{
    melodi_radio_u8 payload[MELODI_RADIO_RESULT_SIZE];

    if (!report || !report->cookie ||
        report->result > MELODI_RADIO_RESULT_DUTY)
        return -EINVAL;
    melodi_radio_put_u32(payload, report->cookie);
    melodi_radio_put_u32(payload + 4, report->duration_us);
    payload[8] = report->result;
    payload[9] = 0;
    return melodi_radio_stream_encode(MELODI_RADIO_T_RESULT, payload,
                                      sizeof(payload), output, capacity,
                                      encoded_length);
}

int melodi_radio_decode_result(const void *input, size_t length,
                               struct melodi_radio_result_report *report)
{
    const melodi_radio_u8 *payload = input;

    if (!input || !report || length != MELODI_RADIO_RESULT_SIZE)
        return -EINVAL;
    memset(report, 0, sizeof(*report));
    report->cookie = melodi_radio_get_u32(payload);
    report->duration_us = melodi_radio_get_u32(payload + 4);
    report->result = payload[8];
    if (!report->cookie || report->result > MELODI_RADIO_RESULT_DUTY)
        return -EPROTO;
    return 0;
}

/**
 * melodi_radio_airtime_estimate - Semtech LoRa time on air
 * @spreading_factor: 6 to 12
 * @bandwidth_khz: channel bandwidth in kilohertz
 * @coding_rate: 5 to 8, the denominator of 4/N
 * @payload_length: physical payload octets
 * @duration_us: filled with the transmission duration in microseconds
 *
 * Assumes an eight symbol preamble, explicit header and enabled CRC.
 */
int melodi_radio_airtime_estimate(melodi_radio_u8 spreading_factor,
                                  melodi_radio_u16 bandwidth_khz,
                                  melodi_radio_u8 coding_rate,
                                  size_t payload_length,
                                  melodi_radio_u32 *duration_us)
{
    unsigned long long symbol_us;
    unsigned long long preamble_us;
    unsigned long long payload_us;
    long long numerator;
    long long denominator;
    long long symbols;
    unsigned int low_rate;

    if (!duration_us || spreading_factor < 6 || spreading_factor > 12 ||
        !bandwidth_khz || coding_rate < 5 || coding_rate > 8 ||
        payload_length > MELODI_RADIO_PACKET_MAX)
        return -EINVAL;
    symbol_us = ((unsigned long long)1 << spreading_factor) * 1000ULL /
                bandwidth_khz;
    preamble_us = symbol_us * 49ULL / 4ULL;
    low_rate = spreading_factor >= 11 && bandwidth_khz <= 125 ? 1 : 0;
    numerator = 8LL * (long long)payload_length -
                4LL * spreading_factor + 28LL + 16LL;
    denominator = 4LL * (spreading_factor - 2LL * low_rate);
    if (denominator <= 0)
        return -EINVAL;
    symbols = numerator <= 0 ? 0 :
              (numerator + denominator - 1) / denominator;
    symbols = 8 + symbols * (coding_rate - 4LL + 4LL);
    payload_us = (unsigned long long)symbols * symbol_us;
    *duration_us = (melodi_radio_u32)(preamble_us + payload_us);
    return 0;
}

int melodi_radio_segment_encode(const struct melodi_radio_segment *segment,
                                void *output, size_t capacity,
                                size_t *encoded_length)
{
    melodi_radio_u8 *out = output;

    if (!segment || !output || !encoded_length || !segment->frame_id ||
        !segment->count || segment->count > MELODI_RADIO_SEGMENT_LIMIT ||
        segment->index >= segment->count || !segment->payload ||
        !segment->payload_length || !segment->total_length ||
        segment->total_length > MELODI_RADIO_FRAME_MAX ||
        segment->payload_length >
            MELODI_RADIO_PACKET_MAX - MELODI_RADIO_SEGMENT_SIZE)
        return -EINVAL;
    if (capacity < (size_t)MELODI_RADIO_SEGMENT_SIZE + segment->payload_length)
        return -ENOSPC;
    melodi_radio_put_u32(out, segment->frame_id);
    melodi_radio_put_u16(out + 4, segment->total_length);
    melodi_radio_put_u16(out + 6, segment->index);
    melodi_radio_put_u16(out + 8, segment->count);
    melodi_radio_put_u16(out + 10, 0);
    memcpy(out + MELODI_RADIO_SEGMENT_SIZE, segment->payload,
           segment->payload_length);
    *encoded_length = MELODI_RADIO_SEGMENT_SIZE + segment->payload_length;
    return 0;
}

int melodi_radio_segment_decode(const void *input, size_t length,
                                struct melodi_radio_segment *segment)
{
    const melodi_radio_u8 *payload = input;

    if (!input || !segment || length <= MELODI_RADIO_SEGMENT_SIZE ||
        length > MELODI_RADIO_PACKET_MAX)
        return -EINVAL;
    memset(segment, 0, sizeof(*segment));
    segment->frame_id = melodi_radio_get_u32(payload);
    segment->total_length = melodi_radio_get_u16(payload + 4);
    segment->index = melodi_radio_get_u16(payload + 6);
    segment->count = melodi_radio_get_u16(payload + 8);
    segment->payload = payload + MELODI_RADIO_SEGMENT_SIZE;
    segment->payload_length =
        (melodi_radio_u16)(length - MELODI_RADIO_SEGMENT_SIZE);
    if (!segment->frame_id || !segment->count ||
        segment->count > MELODI_RADIO_SEGMENT_LIMIT ||
        segment->index >= segment->count || !segment->total_length ||
        segment->total_length > MELODI_RADIO_FRAME_MAX)
        return -EPROTO;
    return 0;
}
