/* SPDX-License-Identifier: GPL-2.0-only */
#include "meshtastic.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

struct melodi_proto_reader {
    const melodi_mesh_u8 *position;
    size_t remaining;
};

struct melodi_proto_writer {
    melodi_mesh_u8 *output;
    size_t capacity;
    size_t length;
};

#define MELODI_PROTO_FIELD_LIMIT 64

static int melodi_proto_varint(struct melodi_proto_reader *reader,
                               unsigned long long *value)
{
    unsigned int shift;
    melodi_mesh_u8 byte;

    *value = 0;
    for (shift = 0; shift < 70; shift += 7) {
        if (!reader->remaining)
            return -EMSGSIZE;
        byte = *reader->position++;
        reader->remaining--;
        if (shift == 63 && byte > 1)
            return -EPROTO;
        *value |= (unsigned long long)(byte & 0x7f) << shift;
        if (!(byte & 0x80))
            return 0;
    }
    return -EPROTO;
}

static int melodi_proto_bytes(struct melodi_proto_reader *reader,
                              const melodi_mesh_u8 **value, size_t *length)
{
    unsigned long long encoded_length;
    int error;

    error = melodi_proto_varint(reader, &encoded_length);
    if (error)
        return error;
    if (encoded_length > reader->remaining)
        return -EMSGSIZE;
    *value = reader->position;
    *length = encoded_length;
    reader->position += encoded_length;
    reader->remaining -= encoded_length;
    return 0;
}

static melodi_mesh_u32 melodi_proto_fixed32(const melodi_mesh_u8 *input)
{
    return input[0] | (melodi_mesh_u32)input[1] << 8 |
           (melodi_mesh_u32)input[2] << 16 |
           (melodi_mesh_u32)input[3] << 24;
}

static int melodi_proto_skip(struct melodi_proto_reader *reader,
                             unsigned int wire)
{
    const melodi_mesh_u8 *bytes;
    unsigned long long value;
    size_t length;

    if (wire == 0)
        return melodi_proto_varint(reader, &value);
    if (wire == 1) {
        if (reader->remaining < 8)
            return -EMSGSIZE;
        reader->position += 8;
        reader->remaining -= 8;
        return 0;
    }
    if (wire == 2)
        return melodi_proto_bytes(reader, &bytes, &length);
    if (wire == 5) {
        if (reader->remaining < 4)
            return -EMSGSIZE;
        reader->position += 4;
        reader->remaining -= 4;
        return 0;
    }
    return -EPROTO;
}

static int melodi_proto_put(struct melodi_proto_writer *writer,
                            const void *data, size_t length)
{
    if ((!data && length) || length > writer->capacity - writer->length)
        return -EMSGSIZE;
    if (length)
        memcpy(writer->output + writer->length, data, length);
    writer->length += length;
    return 0;
}

static int melodi_proto_put_varint(struct melodi_proto_writer *writer,
                                   unsigned long long value)
{
    melodi_mesh_u8 encoded[10];
    size_t length = 0;

    do {
        encoded[length] = value & 0x7f;
        value >>= 7;
        if (value)
            encoded[length] |= 0x80;
        length++;
    } while (value);
    return melodi_proto_put(writer, encoded, length);
}

static int melodi_proto_put_key(struct melodi_proto_writer *writer,
                                unsigned int field, unsigned int wire)
{
    return field && field < (1U << 29) && wire <= 5 && wire != 3 && wire != 4 ?
           melodi_proto_put_varint(writer,
                                   (unsigned long long)field << 3 | wire) :
           -EINVAL;
}

static int melodi_proto_put_fixed32(struct melodi_proto_writer *writer,
                                    unsigned int field,
                                    melodi_mesh_u32 value)
{
    melodi_mesh_u8 encoded[4] = {
        value, value >> 8, value >> 16, value >> 24,
    };
    int error = melodi_proto_put_key(writer, field, 5);

    return error ? error : melodi_proto_put(writer, encoded, sizeof(encoded));
}

static int melodi_proto_put_field_varint(struct melodi_proto_writer *writer,
                                         unsigned int field,
                                         unsigned long long value)
{
    int error = melodi_proto_put_key(writer, field, 0);

    return error ? error : melodi_proto_put_varint(writer, value);
}

static int melodi_proto_put_bytes(struct melodi_proto_writer *writer,
                                  unsigned int field, const void *value,
                                  size_t length)
{
    int error = melodi_proto_put_key(writer, field, 2);

    if (!error)
        error = melodi_proto_put_varint(writer, length);
    return error ? error : melodi_proto_put(writer, value, length);
}

void melodi_mesh_stream_init(struct melodi_mesh_stream *stream)
{
    if (stream)
        memset(stream, 0, sizeof(*stream));
}

int melodi_mesh_stream_feed(struct melodi_mesh_stream *stream,
                            melodi_mesh_u8 byte,
                            const melodi_mesh_u8 **message, size_t *length)
{
    if (!stream || !message || !length)
        return -EINVAL;
    if (stream->state == MELODI_MESH_SCAN_START1) {
        if (byte == MELODI_MESH_STREAM_START1)
            stream->state = MELODI_MESH_EXPECT_START2;
        return 0;
    }
    if (stream->state == MELODI_MESH_EXPECT_START2) {
        if (byte == MELODI_MESH_STREAM_START2)
            stream->state = MELODI_MESH_READ_LENGTH_HIGH;
        else if (byte != MELODI_MESH_STREAM_START1)
            stream->state = MELODI_MESH_SCAN_START1;
        return 0;
    }
    if (stream->state == MELODI_MESH_READ_LENGTH_HIGH) {
        stream->expected = (melodi_mesh_u16)byte << 8;
        stream->state = MELODI_MESH_READ_LENGTH_LOW;
        return 0;
    }
    if (stream->state == MELODI_MESH_READ_LENGTH_LOW) {
        stream->expected |= byte;
        stream->length = 0;
        if (stream->expected > MELODI_MESH_STREAM_MAX) {
            stream->state = MELODI_MESH_SCAN_START1;
            return -EMSGSIZE;
        }
        if (!stream->expected) {
            *message = stream->buffer;
            *length = 0;
            stream->state = MELODI_MESH_SCAN_START1;
            return 1;
        }
        stream->state = MELODI_MESH_READ_PAYLOAD;
        return 0;
    }
    stream->buffer[stream->length++] = byte;
    if (stream->length != stream->expected)
        return 0;
    *message = stream->buffer;
    *length = stream->length;
    stream->state = MELODI_MESH_SCAN_START1;
    return 1;
}

int melodi_mesh_stream_encode(const void *message, size_t length, void *output,
                              size_t capacity, size_t *encoded_length)
{
    melodi_mesh_u8 *bytes = output;

    if ((!message && length) || !output || !encoded_length ||
        length > MELODI_MESH_STREAM_MAX || capacity < length + 4)
        return -EINVAL;
    bytes[0] = MELODI_MESH_STREAM_START1;
    bytes[1] = MELODI_MESH_STREAM_START2;
    bytes[2] = length >> 8;
    bytes[3] = length;
    if (length)
        memcpy(bytes + 4, message, length);
    *encoded_length = length + 4;
    return 0;
}

static int melodi_mesh_encode_packet(const struct melodi_mesh_packet *packet,
                                     unsigned int outer_field, void *output,
                                     size_t capacity, size_t *encoded_length)
{
    melodi_mesh_u8 data_buffer[MELODI_MESH_DATA_MAX + 32] = { 0 };
    melodi_mesh_u8 packet_buffer[MELODI_MESH_DATA_MAX + 96] = { 0 };
    struct melodi_proto_writer data = {
        .output = data_buffer, .capacity = sizeof(data_buffer),
    };
    struct melodi_proto_writer mesh = {
        .output = packet_buffer, .capacity = sizeof(packet_buffer),
    };
    struct melodi_proto_writer outer = {
        .output = output, .capacity = capacity,
    };
    melodi_mesh_u32 portnum;
    int error;

    if (!packet || !output || !encoded_length || !packet->id || !packet->to ||
        (!packet->payload && packet->payload_length) ||
        packet->payload_length > MELODI_MESH_DATA_MAX ||
        packet->hop_limit > 7 || packet->priority > 127)
        return -EINVAL;
    portnum = packet->portnum ? packet->portnum : MELODI_MESH_PRIVATE_PORT;
    error = melodi_proto_put_field_varint(&data, 1, portnum);
    if (!error)
        error = melodi_proto_put_bytes(&data, 2, packet->payload,
                                       packet->payload_length);
    if (!error && packet->want_response)
        error = melodi_proto_put_field_varint(&data, 3, 1);
    if (!error && packet->request_id)
        error = melodi_proto_put_fixed32(&data, 6, packet->request_id);
    if (!error && packet->reply_id)
        error = melodi_proto_put_fixed32(&data, 7, packet->reply_id);
    if (!error && packet->from)
        error = melodi_proto_put_fixed32(&mesh, 1, packet->from);
    if (!error)
        error = melodi_proto_put_fixed32(&mesh, 2, packet->to);
    if (!error)
        error = melodi_proto_put_bytes(&mesh, 4, data.output, data.length);
    if (!error)
        error = melodi_proto_put_fixed32(&mesh, 6, packet->id);
    if (!error && packet->hop_limit)
        error = melodi_proto_put_field_varint(&mesh, 9, packet->hop_limit);
    if (!error && packet->want_ack)
        error = melodi_proto_put_field_varint(&mesh, 10, 1);
    if (!error && packet->priority)
        error = melodi_proto_put_field_varint(&mesh, 11, packet->priority);
    if (!error)
        error = melodi_proto_put_bytes(&outer, outer_field, mesh.output,
                                       mesh.length);
    if (error)
        return error;
    *encoded_length = outer.length;
    return 0;
}

int melodi_mesh_encode_to_radio(const struct melodi_mesh_packet *packet,
                                void *output, size_t capacity,
                                size_t *encoded_length)
{
    return melodi_mesh_encode_packet(packet, 1, output, capacity,
                                     encoded_length);
}

int melodi_mesh_encode_from_radio(const struct melodi_mesh_packet *packet,
                                  void *output, size_t capacity,
                                  size_t *encoded_length)
{
    if (!packet || !packet->from)
        return -EINVAL;
    return melodi_mesh_encode_packet(packet, 2, output, capacity,
                                     encoded_length);
}

int melodi_mesh_encode_routing_response(
    melodi_mesh_u32 from, melodi_mesh_u32 to, melodi_mesh_u32 packet_id,
    melodi_mesh_u32 request_id, melodi_mesh_s32 result, void *output,
    size_t capacity, size_t *encoded_length)
{
    melodi_mesh_u8 routing[12] = { 0 };
    struct melodi_proto_writer writer = {
        .output = routing, .capacity = sizeof(routing),
    };
    struct melodi_mesh_packet packet = {
        .portnum = MELODI_MESH_ROUTING_PORT,
        .from = from,
        .to = to,
        .id = packet_id,
        .request_id = request_id,
    };
    int error;

    if (!from || !to || !packet_id || !request_id || !output ||
        !encoded_length)
        return -EINVAL;
    error = melodi_proto_put_field_varint(
        &writer, 3, (unsigned long long)(long long)result);
    if (error)
        return error;
    packet.payload = writer.output;
    packet.payload_length = writer.length;
    return melodi_mesh_encode_from_radio(&packet, output, capacity,
                                         encoded_length);
}

int melodi_mesh_encode_want_config(melodi_mesh_u32 nonce, void *output,
                                   size_t capacity, size_t *encoded_length)
{
    struct melodi_proto_writer writer = {
        .output = output, .capacity = capacity,
    };
    int error;

    if (!nonce || !output || !encoded_length)
        return -EINVAL;
    error = melodi_proto_put_field_varint(&writer, 3, nonce);
    if (error)
        return error;
    *encoded_length = writer.length;
    return 0;
}

int melodi_mesh_encode_heartbeat(melodi_mesh_u32 nonce, void *output,
                                 size_t capacity, size_t *encoded_length)
{
    melodi_mesh_u8 heartbeat[10] = { 0 };
    struct melodi_proto_writer inner = {
        .output = heartbeat, .capacity = sizeof(heartbeat),
    };
    struct melodi_proto_writer outer = {
        .output = output, .capacity = capacity,
    };
    int error = 0;

    if (!output || !encoded_length)
        return -EINVAL;
    if (nonce)
        error = melodi_proto_put_field_varint(&inner, 1, nonce);
    if (!error)
        error = melodi_proto_put_bytes(&outer, 7, inner.output, inner.length);
    if (error)
        return error;
    *encoded_length = outer.length;
    return 0;
}

int melodi_mesh_encode_my_info(melodi_mesh_u32 node_number, void *output,
                               size_t capacity, size_t *encoded_length)
{
    melodi_mesh_u8 info[10] = { 0 };
    struct melodi_proto_writer inner = {
        .output = info, .capacity = sizeof(info),
    };
    struct melodi_proto_writer outer = {
        .output = output, .capacity = capacity,
    };
    int error;

    if (!node_number || !output || !encoded_length)
        return -EINVAL;
    error = melodi_proto_put_field_varint(&inner, 1, node_number);
    if (!error)
        error = melodi_proto_put_bytes(&outer, 3, inner.output, inner.length);
    if (error)
        return error;
    *encoded_length = outer.length;
    return 0;
}

static int melodi_proto_int32(unsigned long long value,
                              melodi_mesh_s32 *decoded)
{
    melodi_mesh_s32 result = (melodi_mesh_s32)value;

    if ((unsigned long long)(long long)result != value)
        return -EPROTO;
    *decoded = result;
    return 0;
}

static int melodi_mesh_decode_data(const void *input, size_t length,
                                   struct melodi_mesh_packet *packet)
{
    struct melodi_proto_reader reader = { .position = input,
                                           .remaining = length };
    const melodi_mesh_u8 *payload;
    unsigned long long key;
    unsigned long long value;
    size_t payload_length;
    unsigned int fields = 0;
    bool have_port = false;
    bool have_payload = false;
    int error;

    while (reader.remaining) {
        if (++fields > MELODI_PROTO_FIELD_LIMIT)
            return -E2BIG;
        error = melodi_proto_varint(&reader, &key);
        if (error || !(key >> 3))
            return error ? error : -EPROTO;
        if ((key >> 3) == 1 && (key & 7) == 0) {
            if (have_port)
                return -EPROTO;
            error = melodi_proto_varint(&reader, &value);
            if (error || !value || value > 0xffffffffULL)
                return error ? error : -EPROTO;
            packet->portnum = value;
            have_port = true;
        } else if ((key >> 3) == 2 && (key & 7) == 2) {
            if (have_payload)
                return -EPROTO;
            error = melodi_proto_bytes(&reader, &payload, &payload_length);
            if (error || payload_length > MELODI_MESH_DATA_MAX)
                return error ? error : -EMSGSIZE;
            packet->payload = payload;
            packet->payload_length = payload_length;
            have_payload = true;
        } else if ((key >> 3) == 3 && (key & 7) == 0) {
            error = melodi_proto_varint(&reader, &value);
            if (error || value > 1)
                return error ? error : -EPROTO;
            packet->want_response = value;
        } else if (((key >> 3) == 6 || (key >> 3) == 7) &&
                   (key & 7) == 5) {
            if (reader.remaining < 4)
                return -EMSGSIZE;
            value = melodi_proto_fixed32(reader.position);
            reader.position += 4;
            reader.remaining -= 4;
            if ((key >> 3) == 6)
                packet->request_id = value;
            else
                packet->reply_id = value;
        } else {
            error = melodi_proto_skip(&reader, key & 7);
            if (error)
                return error;
        }
    }
    return have_port && have_payload ? 0 : -EPROTO;
}

static int melodi_mesh_decode_packet(const void *input, size_t length,
                                     struct melodi_mesh_packet *packet)
{
    struct melodi_proto_reader reader = { .position = input,
                                           .remaining = length };
    const melodi_mesh_u8 *decoded = NULL;
    unsigned long long key;
    unsigned long long value;
    size_t decoded_length = 0;
    unsigned long long seen = 0;
    unsigned int fields = 0;
    unsigned int field;
    unsigned int wire;
    int error;

    while (reader.remaining) {
        if (++fields > MELODI_PROTO_FIELD_LIMIT)
            return -E2BIG;
        error = melodi_proto_varint(&reader, &key);
        if (error)
            return error;
        field = key >> 3;
        wire = key & 7;
        if (!field)
            return -EPROTO;
        if (field < 64 && seen & (1ULL << field))
            return -EPROTO;
        if ((field == 1 || field == 2 || field == 6 || field == 8) &&
            wire == 5) {
            if (reader.remaining < 4)
                return -EMSGSIZE;
            value = melodi_proto_fixed32(reader.position);
            reader.position += 4;
            reader.remaining -= 4;
            if (field == 1)
                packet->from = value;
            else if (field == 2)
                packet->to = value;
            else if (field == 6)
                packet->id = value;
            else
                packet->snr_bits = value;
        } else if (field == 4 && wire == 2) {
            error = melodi_proto_bytes(&reader, &decoded, &decoded_length);
            if (error)
                return error;
        } else if ((field == 9 || field == 10 || field == 11 ||
                    field == 12 || field == 14 || field == 15 ||
                    field == 21) && wire == 0) {
            error = melodi_proto_varint(&reader, &value);
            if (error)
                return error;
            if (field == 9 && value <= 7)
                packet->hop_limit = value;
            else if (field == 10 && value <= 1)
                packet->want_ack = value;
            else if (field == 11 && value <= 127)
                packet->priority = value;
            else if (field == 12)
                error = melodi_proto_int32(value, &packet->rssi);
            else if (field == 14 && value <= 1)
                packet->via_mqtt = value;
            else if (field == 15 && value <= 7)
                packet->hop_start = value;
            else if (field == 21 && value <= 255)
                packet->transport = value;
            else
                return -EPROTO;
            if (error)
                return error;
        } else if (field == 5)
            return -EKEYREJECTED;
        else {
            error = melodi_proto_skip(&reader, wire);
            if (error)
                return error;
        }
        if (field < 64)
            seen |= 1ULL << field;
    }
    if (!packet->from || !packet->to || !decoded)
        return -EPROTO;
    return melodi_mesh_decode_data(decoded, decoded_length, packet);
}

static int melodi_mesh_decode_my_info(const void *input, size_t length,
                                      struct melodi_mesh_event *event)
{
    struct melodi_proto_reader reader = { .position = input,
                                           .remaining = length };
    unsigned long long key;
    unsigned long long value;
    unsigned int fields = 0;
    bool found = false;
    int error;

    while (reader.remaining) {
        if (++fields > MELODI_PROTO_FIELD_LIMIT)
            return -E2BIG;
        error = melodi_proto_varint(&reader, &key);
        if (error || !(key >> 3))
            return error ? error : -EPROTO;
        if ((key >> 3) == 1 && (key & 7) == 0) {
            if (found)
                return -EPROTO;
            error = melodi_proto_varint(&reader, &value);
            if (error || !value || value > 0xffffffffULL)
                return error ? error : -EPROTO;
            event->value = value;
            found = true;
        } else {
            error = melodi_proto_skip(&reader, key & 7);
            if (error)
                return error;
        }
    }
    return found ? 0 : -EPROTO;
}

static int melodi_mesh_decode_lora_inner(const void *input, size_t length,
                                         struct melodi_mesh_event *event)
{
    struct melodi_proto_reader reader = { .position = input,
                                           .remaining = length };
    unsigned long long key;
    unsigned long long value;
    unsigned int fields = 0;
    int error;

    while (reader.remaining) {
        if (++fields > MELODI_PROTO_FIELD_LIMIT)
            return -E2BIG;
        error = melodi_proto_varint(&reader, &key);
        if (error || !(key >> 3))
            return error ? error : -EPROTO;
        if (((key >> 3) == 1 || (key >> 3) == 2 || (key >> 3) == 7 ||
             (key >> 3) == 8 || (key >> 3) == 9 || (key >> 3) == 11 ||
             (key >> 3) == 12 || (key >> 3) == 104) &&
            (key & 7) == 0) {
            error = melodi_proto_varint(&reader, &value);
            if (error || value > 0xffffffffULL)
                return error ? error : -EPROTO;
            if ((key >> 3) == 1 && value <= 1)
                event->lora.use_preset = value;
            else if ((key >> 3) == 2)
                event->lora.modem_preset = value;
            else if ((key >> 3) == 7)
                event->lora.region = value;
            else if ((key >> 3) == 8 && value <= 7)
                event->lora.hop_limit = value;
            else if ((key >> 3) == 9 && value <= 1)
                event->lora.tx_enabled = value;
            else if ((key >> 3) == 11)
                event->lora.channel_num = value;
            else if ((key >> 3) == 12 && value <= 1)
                event->lora.override_duty_cycle = value;
            else if ((key >> 3) == 104 && value <= 1)
                event->lora.ignore_mqtt = value;
            else
                return -EPROTO;
        } else {
            error = melodi_proto_skip(&reader, key & 7);
            if (error)
                return error;
        }
    }
    return 0;
}

static int melodi_mesh_decode_lora(const void *input, size_t length,
                                   struct melodi_mesh_event *event)
{
    struct melodi_proto_reader reader = { .position = input,
                                           .remaining = length };
    const melodi_mesh_u8 *lora;
    unsigned long long key;
    size_t lora_length;
    unsigned int fields = 0;
    int error;

    while (reader.remaining) {
        if (++fields > MELODI_PROTO_FIELD_LIMIT)
            return -E2BIG;
        error = melodi_proto_varint(&reader, &key);
        if (error || !(key >> 3))
            return error ? error : -EPROTO;
        if ((key >> 3) == 6 && (key & 7) == 2) {
            error = melodi_proto_bytes(&reader, &lora, &lora_length);
            if (error)
                return error;
            return melodi_mesh_decode_lora_inner(lora, lora_length, event);
        }
        error = melodi_proto_skip(&reader, key & 7);
        if (error)
            return error;
    }
    return -ENOMSG;
}

static int melodi_mesh_decode_mqtt_inner(const void *input, size_t length,
                                         struct melodi_mesh_event *event)
{
    struct melodi_proto_reader reader = { .position = input,
                                           .remaining = length };
    unsigned long long key;
    unsigned long long value;
    unsigned int fields = 0;
    bool found = false;
    int error;

    while (reader.remaining) {
        if (++fields > MELODI_PROTO_FIELD_LIMIT)
            return -E2BIG;
        error = melodi_proto_varint(&reader, &key);
        if (error || !(key >> 3))
            return error ? error : -EPROTO;
        if ((key >> 3) == 1 && (key & 7) == 0) {
            if (found)
                return -EPROTO;
            error = melodi_proto_varint(&reader, &value);
            if (error || value > 1)
                return error ? error : -EPROTO;
            event->enabled = value;
            found = true;
        } else {
            error = melodi_proto_skip(&reader, key & 7);
            if (error)
                return error;
        }
    }
    return 0;
}

static int melodi_mesh_decode_mqtt(const void *input, size_t length,
                                   struct melodi_mesh_event *event)
{
    struct melodi_proto_reader reader = { .position = input,
                                           .remaining = length };
    const melodi_mesh_u8 *mqtt;
    unsigned long long key;
    size_t mqtt_length;
    unsigned int fields = 0;
    int error;

    while (reader.remaining) {
        if (++fields > MELODI_PROTO_FIELD_LIMIT)
            return -E2BIG;
        error = melodi_proto_varint(&reader, &key);
        if (error || !(key >> 3))
            return error ? error : -EPROTO;
        if ((key >> 3) == 1 && (key & 7) == 2) {
            error = melodi_proto_bytes(&reader, &mqtt, &mqtt_length);
            if (error)
                return error;
            return melodi_mesh_decode_mqtt_inner(mqtt, mqtt_length, event);
        }
        error = melodi_proto_skip(&reader, key & 7);
        if (error)
            return error;
    }
    return -ENOMSG;
}

static int melodi_mesh_decode_channel_settings(
    const void *input, size_t length, struct melodi_mesh_event *event)
{
    struct melodi_proto_reader reader = { .position = input,
                                           .remaining = length };
    unsigned long long key;
    unsigned long long value;
    unsigned int fields = 0;
    int error;

    event->channel.has_settings = true;
    while (reader.remaining) {
        if (++fields > MELODI_PROTO_FIELD_LIMIT)
            return -E2BIG;
        error = melodi_proto_varint(&reader, &key);
        if (error || !(key >> 3))
            return error ? error : -EPROTO;
        if (((key >> 3) == 5 || (key >> 3) == 6) && (key & 7) == 0) {
            error = melodi_proto_varint(&reader, &value);
            if (error || value > 1)
                return error ? error : -EPROTO;
            if ((key >> 3) == 5)
                event->channel.uplink_enabled = value;
            else
                event->channel.downlink_enabled = value;
        } else {
            error = melodi_proto_skip(&reader, key & 7);
            if (error)
                return error;
        }
    }
    return 0;
}

static int melodi_mesh_decode_channel(const void *input, size_t length,
                                      struct melodi_mesh_event *event)
{
    struct melodi_proto_reader reader = { .position = input,
                                           .remaining = length };
    const melodi_mesh_u8 *settings;
    unsigned long long key;
    unsigned long long value;
    size_t settings_length;
    unsigned int fields = 0;
    int error;

    while (reader.remaining) {
        if (++fields > MELODI_PROTO_FIELD_LIMIT)
            return -E2BIG;
        error = melodi_proto_varint(&reader, &key);
        if (error || !(key >> 3))
            return error ? error : -EPROTO;
        if ((key >> 3) == 1 && (key & 7) == 0) {
            error = melodi_proto_varint(&reader, &value);
            if (!error)
                error = melodi_proto_int32(value, &event->channel.index);
        } else if ((key >> 3) == 2 && (key & 7) == 2) {
            error = melodi_proto_bytes(&reader, &settings, &settings_length);
            if (!error)
                error = melodi_mesh_decode_channel_settings(
                    settings, settings_length, event);
        } else if ((key >> 3) == 3 && (key & 7) == 0) {
            error = melodi_proto_varint(&reader, &value);
            if (!error && value <= 2)
                event->channel.role = value;
            else if (!error)
                error = -EPROTO;
        } else {
            error = melodi_proto_skip(&reader, key & 7);
        }
        if (error)
            return error;
    }
    return 0;
}

static int melodi_mesh_decode_queue(const void *input, size_t length,
                                    struct melodi_mesh_event *event)
{
    struct melodi_proto_reader reader = { .position = input,
                                           .remaining = length };
    unsigned long long key;
    unsigned long long value;
    unsigned long long seen = 0;
    unsigned int fields = 0;
    unsigned int field;
    int error;

    while (reader.remaining) {
        if (++fields > MELODI_PROTO_FIELD_LIMIT)
            return -E2BIG;
        error = melodi_proto_varint(&reader, &key);
        field = key >> 3;
        if (error || !field || field > 4 || (key & 7))
            return error ? error : -EPROTO;
        if (seen & (1ULL << field))
            return -EPROTO;
        error = melodi_proto_varint(&reader, &value);
        if (error)
            return error;
        if (field == 1)
            error = melodi_proto_int32(value, &event->queue.result);
        else if (value > 0xffffffffULL)
            error = -EPROTO;
        else if (field == 2)
            event->queue.free = value;
        else if (field == 3)
            event->queue.maximum = value;
        else
            event->queue.packet_id = value;
        if (error)
            return error;
        seen |= 1ULL << field;
    }
    return 0;
}

static int melodi_mesh_decode_metadata(const void *input, size_t length,
                                       struct melodi_mesh_event *event)
{
    struct melodi_proto_reader reader = { .position = input,
                                           .remaining = length };
    const melodi_mesh_u8 *firmware;
    unsigned long long key;
    unsigned long long value;
    size_t firmware_length;
    unsigned long long seen = 0;
    unsigned int fields = 0;
    unsigned int field;
    int error;

    while (reader.remaining) {
        if (++fields > MELODI_PROTO_FIELD_LIMIT)
            return -E2BIG;
        error = melodi_proto_varint(&reader, &key);
        field = key >> 3;
        if (error || !field)
            return error ? error : -EPROTO;
        if (field < 64 && seen & (1ULL << field))
            return -EPROTO;
        if (field == 1 && (key & 7) == 2) {
            error = melodi_proto_bytes(&reader, &firmware, &firmware_length);
            if (error || !firmware_length ||
                firmware_length > MELODI_MESH_FIRMWARE_MAX)
                return error ? error : -EMSGSIZE;
            event->metadata.firmware = firmware;
            event->metadata.firmware_length = firmware_length;
        } else if ((field == 2 || field == 7 || field == 9) &&
                   (key & 7) == 0) {
            error = melodi_proto_varint(&reader, &value);
            if (error || value > 0xffffffffULL)
                return error ? error : -EPROTO;
            if (field == 2)
                event->metadata.device_state_version = value;
            else if (field == 7)
                event->metadata.role = value;
            else
                event->metadata.hardware_model = value;
        } else {
            error = melodi_proto_skip(&reader, key & 7);
            if (error)
                return error;
        }
        if (field < 64)
            seen |= 1ULL << field;
    }
    return event->metadata.firmware ? 0 : -EPROTO;
}

int melodi_mesh_decode_from_radio_event(const void *input, size_t length,
                                        struct melodi_mesh_event *event)
{
    struct melodi_proto_reader reader = { .position = input,
                                           .remaining = length };
    const melodi_mesh_u8 *message;
    unsigned long long key;
    unsigned long long value;
    size_t message_length;
    unsigned int fields = 0;
    unsigned int field;
    unsigned int wire;
    bool found = false;
    int error;

    if (!input || !event || !length || length > MELODI_MESH_STREAM_MAX)
        return -EINVAL;
    memset(event, 0, sizeof(*event));
    while (reader.remaining) {
        if (++fields > MELODI_PROTO_FIELD_LIMIT)
            return -E2BIG;
        error = melodi_proto_varint(&reader, &key);
        if (error || !(key >> 3))
            return error ? error : -EPROTO;
        field = key >> 3;
        wire = key & 7;
        if (field == 1) {
            if (wire != 0)
                return -EPROTO;
            error = melodi_proto_varint(&reader, &value);
            if (error || value > 0xffffffffULL)
                return error ? error : -EPROTO;
            continue;
        }
        if (field == 7 || field == 8) {
            if (found || wire != 0)
                return -EPROTO;
            error = melodi_proto_varint(&reader, &value);
            if (error || value > 0xffffffffULL || (field == 8 && value > 1))
                return error ? error : -EPROTO;
            event->type = field == 7 ? MELODI_MESH_EVENT_CONFIG_COMPLETE :
                                       MELODI_MESH_EVENT_RADIO_RESET;
            event->value = value;
            found = true;
            continue;
        }
        if (field == 2 || field == 3 || field == 5 || field == 9 ||
            field == 10 || field == 11 || field == 13) {
            if (found || wire != 2)
                return -EPROTO;
            error = melodi_proto_bytes(&reader, &message, &message_length);
            if (error)
                return error;
            if (field == 2) {
                event->type = MELODI_MESH_EVENT_PACKET;
                error = melodi_mesh_decode_packet(message, message_length,
                                                  &event->packet);
            } else if (field == 3) {
                event->type = MELODI_MESH_EVENT_MY_INFO;
                error = melodi_mesh_decode_my_info(message, message_length,
                                                   event);
            } else if (field == 5) {
                event->type = MELODI_MESH_EVENT_LORA_CONFIG;
                error = melodi_mesh_decode_lora(message, message_length,
                                                event);
            } else if (field == 9) {
                event->type = MELODI_MESH_EVENT_MQTT_CONFIG;
                error = melodi_mesh_decode_mqtt(message, message_length,
                                                event);
            } else if (field == 10) {
                event->type = MELODI_MESH_EVENT_CHANNEL;
                error = melodi_mesh_decode_channel(message, message_length,
                                                   event);
            } else if (field == 11) {
                event->type = MELODI_MESH_EVENT_QUEUE_STATUS;
                error = melodi_mesh_decode_queue(message, message_length,
                                                 event);
            } else if (field == 13) {
                event->type = MELODI_MESH_EVENT_METADATA;
                error = melodi_mesh_decode_metadata(message, message_length,
                                                    event);
            }
            if (error)
                return error;
            found = true;
            continue;
        }
        error = melodi_proto_skip(&reader, wire);
        if (error)
            return error;
    }
    return found ? 0 : -ENOMSG;
}

static int melodi_mesh_decode_heartbeat(const void *input, size_t length,
                                        melodi_mesh_u32 *nonce)
{
    struct melodi_proto_reader reader = { .position = input,
                                           .remaining = length };
    unsigned long long key;
    unsigned long long value;
    unsigned int fields = 0;
    bool found = false;
    int error;

    *nonce = 0;
    while (reader.remaining) {
        if (++fields > MELODI_PROTO_FIELD_LIMIT)
            return -E2BIG;
        error = melodi_proto_varint(&reader, &key);
        if (error || !(key >> 3))
            return error ? error : -EPROTO;
        if ((key >> 3) == 1 && (key & 7) == 0) {
            if (found)
                return -EPROTO;
            error = melodi_proto_varint(&reader, &value);
            if (error || value > 0xffffffffULL)
                return error ? error : -EPROTO;
            *nonce = value;
            found = true;
        } else {
            error = melodi_proto_skip(&reader, key & 7);
            if (error)
                return error;
        }
    }
    return 0;
}

int melodi_mesh_encode_disconnect(void *output, size_t capacity,
                                  size_t *encoded_length)
{
    struct melodi_proto_writer writer = {
        .output = output, .capacity = capacity,
    };
    int error;

    if (!output || !encoded_length)
        return -EINVAL;
    error = melodi_proto_put_field_varint(&writer, 4, 1);
    if (error)
        return error;
    *encoded_length = writer.length;
    return 0;
}

int melodi_mesh_decode_to_radio(const void *input, size_t length,
                                struct melodi_mesh_command *command)
{
    struct melodi_proto_reader reader = { .position = input,
                                           .remaining = length };
    const melodi_mesh_u8 *message;
    unsigned long long key;
    unsigned long long value;
    size_t message_length;
    unsigned int fields = 0;
    unsigned int field;
    unsigned int wire;
    bool found = false;
    int error;

    if (!input || !command || !length || length > MELODI_MESH_STREAM_MAX)
        return -EINVAL;
    memset(command, 0, sizeof(*command));
    while (reader.remaining) {
        if (++fields > MELODI_PROTO_FIELD_LIMIT)
            return -E2BIG;
        error = melodi_proto_varint(&reader, &key);
        field = key >> 3;
        wire = key & 7;
        if (error || !field)
            return error ? error : -EPROTO;
        if (field == 3) {
            if (found || wire != 0)
                return -EPROTO;
            error = melodi_proto_varint(&reader, &value);
            if (error || !value || value > 0xffffffffULL)
                return error ? error : -EPROTO;
            command->type = MELODI_MESH_COMMAND_CONFIG_REQUEST;
            command->value = value;
            found = true;
            continue;
        }
        if (field == 4) {
            if (found || wire != 0)
                return -EPROTO;
            error = melodi_proto_varint(&reader, &value);
            if (error || value != 1)
                return error ? error : -EPROTO;
            command->type = MELODI_MESH_COMMAND_DISCONNECT;
            command->value = 1;
            found = true;
            continue;
        }
        if (field == 1 || field == 7) {
            if (found || wire != 2)
                return -EPROTO;
            error = melodi_proto_bytes(&reader, &message, &message_length);
            if (error)
                return error;
            if (field == 1) {
                command->type = MELODI_MESH_COMMAND_PACKET;
                error = melodi_mesh_decode_packet(message, message_length,
                                                  &command->packet);
            } else if (field == 7) {
                command->type = MELODI_MESH_COMMAND_HEARTBEAT;
                error = melodi_mesh_decode_heartbeat(message,
                                                     message_length,
                                                     &command->value);
            }
            if (error)
                return error;
            found = true;
            continue;
        }
        error = melodi_proto_skip(&reader, wire);
        if (error)
            return error;
    }
    return found ? 0 : -ENOMSG;
}

int melodi_mesh_decode_from_radio(const void *input, size_t length,
                                  struct melodi_mesh_packet *packet)
{
    struct melodi_mesh_event event;
    int error;

    if (!packet)
        return -EINVAL;
    error = melodi_mesh_decode_from_radio_event(input, length, &event);
    if (error)
        return error;
    if (event.type != MELODI_MESH_EVENT_PACKET ||
        event.packet.portnum != MELODI_MESH_PRIVATE_PORT)
        return -ENOMSG;
    *packet = event.packet;
    return 0;
}

int melodi_mesh_decode_routing(const struct melodi_mesh_packet *packet,
                               melodi_mesh_s32 *result,
                               melodi_mesh_u32 *request_id)
{
    struct melodi_proto_reader reader;
    unsigned long long key;
    unsigned long long value;
    unsigned int fields = 0;
    melodi_mesh_s32 decoded = 0;
    bool found = false;
    int error;

    if (!packet || !result || !request_id ||
        packet->portnum != MELODI_MESH_ROUTING_PORT || !packet->request_id ||
        (!packet->payload && packet->payload_length))
        return -EINVAL;
    reader.position = packet->payload;
    reader.remaining = packet->payload_length;
    while (reader.remaining) {
        if (++fields > MELODI_PROTO_FIELD_LIMIT)
            return -E2BIG;
        error = melodi_proto_varint(&reader, &key);
        if (error || !(key >> 3))
            return error ? error : -EPROTO;
        if ((key >> 3) == 3 && (key & 7) == 0) {
            if (found)
                return -EPROTO;
            error = melodi_proto_varint(&reader, &value);
            if (!error)
                error = melodi_proto_int32(value, &decoded);
            if (error)
                return error;
            found = true;
        } else {
            error = melodi_proto_skip(&reader, key & 7);
            if (error)
                return error;
        }
    }
    *result = decoded;
    *request_id = packet->request_id;
    return 0;
}

static void melodi_mesh_put16(melodi_mesh_u8 *output, melodi_mesh_u16 value)
{
    output[0] = value >> 8;
    output[1] = value;
}

static void melodi_mesh_put32(melodi_mesh_u8 *output, melodi_mesh_u32 value)
{
    output[0] = value >> 24;
    output[1] = value >> 16;
    output[2] = value >> 8;
    output[3] = value;
}

static melodi_mesh_u16 melodi_mesh_get16(const melodi_mesh_u8 *input)
{
    return (melodi_mesh_u16)input[0] << 8 | input[1];
}

static melodi_mesh_u32 melodi_mesh_get32(const melodi_mesh_u8 *input)
{
    return (melodi_mesh_u32)input[0] << 24 |
           (melodi_mesh_u32)input[1] << 16 |
           (melodi_mesh_u32)input[2] << 8 | input[3];
}

int melodi_mesh_segment_encode(const struct melodi_mesh_segment *segment,
                               void *output, size_t capacity,
                               size_t *encoded_length)
{
    melodi_mesh_u8 *bytes = output;
    size_t offset;
    size_t expected_length;
    unsigned int expected_count;

    if (!segment || !output || !encoded_length || !segment->frame_id ||
        !segment->total_length ||
        segment->total_length > MELODI_MESH_FRAME_MAX ||
        (!segment->payload && segment->payload_length) ||
        segment->payload_length > MELODI_MESH_FRAME_MTU ||
        capacity < (size_t)MELODI_MESH_SEGMENT_SIZE +
                   segment->payload_length)
        return -EINVAL;
    expected_count = (segment->total_length + MELODI_MESH_FRAME_MTU - 1) /
                     MELODI_MESH_FRAME_MTU;
    if (segment->count != expected_count ||
        segment->count > MELODI_MESH_SEGMENT_LIMIT ||
        segment->index >= segment->count)
        return -EINVAL;
    offset = (size_t)segment->index * MELODI_MESH_FRAME_MTU;
    expected_length = segment->total_length - offset;
    if (expected_length > MELODI_MESH_FRAME_MTU)
        expected_length = MELODI_MESH_FRAME_MTU;
    if (segment->payload_length != expected_length)
        return -EINVAL;
    bytes[0] = 'M';
    bytes[1] = 'L';
    bytes[2] = 1;
    bytes[3] = 0;
    melodi_mesh_put32(bytes + 4, segment->frame_id);
    melodi_mesh_put16(bytes + 8, segment->total_length);
    melodi_mesh_put16(bytes + 10, segment->index);
    melodi_mesh_put16(bytes + 12, segment->count);
    melodi_mesh_put16(bytes + 14, segment->payload_length);
    memcpy(bytes + MELODI_MESH_SEGMENT_SIZE, segment->payload,
           segment->payload_length);
    *encoded_length = MELODI_MESH_SEGMENT_SIZE + segment->payload_length;
    return 0;
}

int melodi_mesh_segment_decode(const void *input, size_t length,
                               struct melodi_mesh_segment *segment)
{
    const melodi_mesh_u8 *bytes = input;
    size_t offset;
    size_t expected_length;
    unsigned int expected_count;

    if (!input || !segment || length < MELODI_MESH_SEGMENT_SIZE ||
        length > MELODI_MESH_DATA_MAX)
        return -EINVAL;
    if (bytes[0] != 'M' || bytes[1] != 'L' || bytes[2] != 1 || bytes[3])
        return -EPROTO;
    segment->frame_id = melodi_mesh_get32(bytes + 4);
    segment->total_length = melodi_mesh_get16(bytes + 8);
    segment->index = melodi_mesh_get16(bytes + 10);
    segment->count = melodi_mesh_get16(bytes + 12);
    segment->payload_length = melodi_mesh_get16(bytes + 14);
    segment->payload = bytes + MELODI_MESH_SEGMENT_SIZE;
    if (!segment->frame_id || !segment->total_length ||
        segment->total_length > MELODI_MESH_FRAME_MAX ||
        segment->payload_length != length - MELODI_MESH_SEGMENT_SIZE ||
        segment->payload_length > segment->total_length)
        return -EPROTO;
    expected_count = (segment->total_length + MELODI_MESH_FRAME_MTU - 1) /
                     MELODI_MESH_FRAME_MTU;
    if (segment->count != expected_count ||
        segment->count > MELODI_MESH_SEGMENT_LIMIT ||
        segment->index >= segment->count)
        return -EPROTO;
    offset = (size_t)segment->index * MELODI_MESH_FRAME_MTU;
    expected_length = segment->total_length - offset;
    if (expected_length > MELODI_MESH_FRAME_MTU)
        expected_length = MELODI_MESH_FRAME_MTU;
    if (segment->payload_length != expected_length)
        return -EPROTO;
    return 0;
}

int melodi_mesh_region_duty_permille(melodi_mesh_u32 region,
                                     melodi_mesh_u16 *permille)
{
    if (!permille)
        return -EINVAL;
    switch (region) {
    case 2:
    case 3:
    case 12:
    case 14:
    case 32:
        *permille = 100;
        return 0;
    case 29:
        *permille = 25;
        return 0;
    case 1:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
    case 11:
    case 13:
    case 16:
    case 17:
    case 18:
    case 19:
    case 20:
    case 21:
    case 22:
    case 23:
    case 24:
    case 25:
    case 26:
    case 27:
    case 28:
    case 33:
    case 34:
    case 35:
    case 36:
    case 37:
        *permille = 1000;
        return 0;
    default:
        return -EOPNOTSUPP;
    }
}

static int melodi_mesh_modem(melodi_mesh_u32 preset, bool wide_lora,
                             melodi_mesh_u32 *bandwidth_hz,
                             melodi_mesh_u8 *spreading_factor,
                             melodi_mesh_u8 *coding_rate)
{
    switch (preset) {
    case 0:
        *bandwidth_hz = wide_lora ? 812500 : 250000;
        *spreading_factor = 11;
        *coding_rate = 5;
        return 0;
    case 1:
        *bandwidth_hz = wide_lora ? 406250 : 125000;
        *spreading_factor = 12;
        *coding_rate = 8;
        return 0;
    case 3:
        *bandwidth_hz = wide_lora ? 812500 : 250000;
        *spreading_factor = 10;
        *coding_rate = 5;
        return 0;
    case 4:
        *bandwidth_hz = wide_lora ? 812500 : 250000;
        *spreading_factor = 9;
        *coding_rate = 5;
        return 0;
    case 5:
        *bandwidth_hz = wide_lora ? 812500 : 250000;
        *spreading_factor = 8;
        *coding_rate = 5;
        return 0;
    case 6:
        *bandwidth_hz = wide_lora ? 812500 : 250000;
        *spreading_factor = 7;
        *coding_rate = 5;
        return 0;
    case 7:
        *bandwidth_hz = wide_lora ? 406250 : 125000;
        *spreading_factor = 11;
        *coding_rate = 8;
        return 0;
    case 8:
        *bandwidth_hz = wide_lora ? 1625000 : 500000;
        *spreading_factor = 7;
        *coding_rate = 5;
        return 0;
    case 9:
        *bandwidth_hz = wide_lora ? 1625000 : 500000;
        *spreading_factor = 11;
        *coding_rate = 8;
        return 0;
    case 10:
        *bandwidth_hz = 125000;
        *spreading_factor = 9;
        *coding_rate = 5;
        return 0;
    case 11:
        *bandwidth_hz = 125000;
        *spreading_factor = 10;
        *coding_rate = 5;
        return 0;
    case 12:
        *bandwidth_hz = 62500;
        *spreading_factor = 7;
        *coding_rate = 6;
        return 0;
    case 13:
        *bandwidth_hz = 62500;
        *spreading_factor = 8;
        *coding_rate = 6;
        return 0;
    case 14:
        *bandwidth_hz = 15625;
        *spreading_factor = 7;
        *coding_rate = 5;
        return 0;
    case 15:
        *bandwidth_hz = 15625;
        *spreading_factor = 8;
        *coding_rate = 6;
        return 0;
    case 16:
        *bandwidth_hz = wide_lora ? 1625000 : 500000;
        *spreading_factor = 9;
        *coding_rate = 5;
        return 0;
    default:
        return -EOPNOTSUPP;
    }
}

int melodi_mesh_airtime_estimate(melodi_mesh_u32 modem_preset,
                                 bool wide_lora, size_t frame_length,
                                 melodi_mesh_u64 *airtime_us)
{
    melodi_mesh_u32 bandwidth_hz;
    melodi_mesh_u64 numerator;
    melodi_mesh_u64 payload_symbols;
    melodi_mesh_u64 preamble_quarters;
    melodi_mesh_u64 symbol_us;
    melodi_mesh_u64 packet_us;
    melodi_mesh_u8 spreading_factor;
    melodi_mesh_u8 coding_rate;
    unsigned int count;
    bool low_data_rate;
    int error;

    if (!airtime_us || !frame_length ||
        frame_length > MELODI_MESH_FRAME_MAX)
        return -EINVAL;
    error = melodi_mesh_modem(modem_preset, wide_lora, &bandwidth_hz,
                              &spreading_factor, &coding_rate);
    if (error)
        return error;
    count = (frame_length + MELODI_MESH_FRAME_MTU - 1) /
            MELODI_MESH_FRAME_MTU;
    symbol_us = (((melodi_mesh_u64)1 << spreading_factor) * 1000000 +
                 bandwidth_hz - 1) / bandwidth_hz;
    low_data_rate = symbol_us > 16000;
    numerator = 8 * 255 - 4 * spreading_factor + 28 + 16;
    payload_symbols = 8 +
        ((numerator + 4 * (spreading_factor - 2 * low_data_rate) - 1) /
         (4 * (spreading_factor - 2 * low_data_rate))) * coding_rate;
    preamble_quarters = 4 * (wide_lora ? 12 : 16) + 17;
    packet_us = (preamble_quarters * symbol_us + 3) / 4 +
                payload_symbols * symbol_us;
    *airtime_us = packet_us * count;
    return 0;
}
