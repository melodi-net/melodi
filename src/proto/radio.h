/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MELODI_RADIO_H
#define MELODI_RADIO_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef u8 melodi_radio_u8;
typedef u16 melodi_radio_u16;
typedef u32 melodi_radio_u32;
typedef s16 melodi_radio_s16;
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef uint8_t melodi_radio_u8;
typedef uint16_t melodi_radio_u16;
typedef uint32_t melodi_radio_u32;
typedef int16_t melodi_radio_s16;
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MELODI_RADIO_MAGIC0 0x4d
#define MELODI_RADIO_MAGIC1 0x4c
#define MELODI_RADIO_VERSION 1
#define MELODI_RADIO_HEADER_SIZE 8
#define MELODI_RADIO_PAYLOAD_MAX 512
#define MELODI_RADIO_PACKET_MAX 240
#define MELODI_RADIO_SEGMENT_SIZE 12
#define MELODI_RADIO_SEGMENT_LIMIT 32
#define MELODI_RADIO_FRAME_MAX \
    ((MELODI_RADIO_PACKET_MAX - MELODI_RADIO_SEGMENT_SIZE) * \
     MELODI_RADIO_SEGMENT_LIMIT)
#define MELODI_RADIO_LOCATOR_BROADCAST 0xffffffffU
#define MELODI_RADIO_DOMAIN_SIZE 32
#define MELODI_RADIO_VERSION_MAX 31

enum melodi_radio_type {
    MELODI_RADIO_T_IDENTIFY = 1,
    MELODI_RADIO_T_CONFIGURE,
    MELODI_RADIO_T_TRANSMIT,
    MELODI_RADIO_T_RESET,
    MELODI_RADIO_T_INFO = 0x81,
    MELODI_RADIO_T_STATUS,
    MELODI_RADIO_T_RECEIVE,
    MELODI_RADIO_T_RESULT,
};

enum melodi_radio_state {
    MELODI_RADIO_STATE_IDLE,
    MELODI_RADIO_STATE_READY,
    MELODI_RADIO_STATE_FAILED,
};

enum melodi_radio_fault {
    MELODI_RADIO_FAULT_NONE,
    MELODI_RADIO_FAULT_HARDWARE,
    MELODI_RADIO_FAULT_REGION,
    MELODI_RADIO_FAULT_MODEM,
    MELODI_RADIO_FAULT_LOCATOR,
    MELODI_RADIO_FAULT_DOMAIN,
    MELODI_RADIO_FAULT_OVERRUN,
    MELODI_RADIO_FAULT_INTERNAL,
};

enum melodi_radio_result {
    MELODI_RADIO_RESULT_SENT,
    MELODI_RADIO_RESULT_BUSY,
    MELODI_RADIO_RESULT_TOO_LARGE,
    MELODI_RADIO_RESULT_NOT_READY,
    MELODI_RADIO_RESULT_HARDWARE,
    MELODI_RADIO_RESULT_DUTY,
};

/**
 * struct melodi_radio_header - framing for every host/radio message
 * @magic0: MELODI_RADIO_MAGIC0
 * @magic1: MELODI_RADIO_MAGIC1
 * @version: MELODI_RADIO_VERSION
 * @type: enum melodi_radio_type
 * @length: payload octets following the header
 * @checksum: ones complement sum over the payload
 */
struct melodi_radio_header {
    melodi_radio_u8 magic0;
    melodi_radio_u8 magic1;
    melodi_radio_u8 version;
    melodi_radio_u8 type;
    melodi_radio_u16 length;
    melodi_radio_u16 checksum;
};

struct melodi_radio_configure {
    melodi_radio_u8 domain[MELODI_RADIO_DOMAIN_SIZE];
    melodi_radio_u32 locator;
    melodi_radio_u32 frequency_hz;
    melodi_radio_u16 bandwidth_khz;
    melodi_radio_u8 spreading_factor;
    melodi_radio_u8 coding_rate;
    melodi_radio_s16 transmit_power_dbm;
    melodi_radio_u16 duty_permille;
};

struct melodi_radio_info {
    char firmware[MELODI_RADIO_VERSION_MAX + 1];
    char hardware[MELODI_RADIO_VERSION_MAX + 1];
    melodi_radio_u32 abi_version;
    melodi_radio_u16 packet_mtu;
    melodi_radio_u16 queue_depth;
};

struct melodi_radio_status {
    melodi_radio_u32 locator;
    melodi_radio_u16 queue_free;
    melodi_radio_u16 queue_depth;
    melodi_radio_u8 state;
    melodi_radio_u8 fault;
};

struct melodi_radio_transmit {
    melodi_radio_u32 cookie;
    melodi_radio_u32 destination;
    const melodi_radio_u8 *payload;
    melodi_radio_u16 payload_length;
};

struct melodi_radio_receive {
    melodi_radio_u32 source;
    melodi_radio_u32 destination;
    melodi_radio_s16 rssi;
    melodi_radio_s16 snr;
    melodi_radio_u8 hops;
    const melodi_radio_u8 *payload;
    melodi_radio_u16 payload_length;
};

struct melodi_radio_result_report {
    melodi_radio_u32 cookie;
    melodi_radio_u32 duration_us;
    melodi_radio_u8 result;
};

struct melodi_radio_segment {
    melodi_radio_u32 frame_id;
    melodi_radio_u16 total_length;
    melodi_radio_u16 index;
    melodi_radio_u16 count;
    const melodi_radio_u8 *payload;
    melodi_radio_u16 payload_length;
};

enum melodi_radio_stream_state {
    MELODI_RADIO_SCAN_MAGIC0,
    MELODI_RADIO_SCAN_MAGIC1,
    MELODI_RADIO_READ_HEADER,
    MELODI_RADIO_READ_PAYLOAD,
};

struct melodi_radio_stream {
    enum melodi_radio_stream_state state;
    melodi_radio_u16 offset;
    melodi_radio_u16 expected;
    struct melodi_radio_header header;
    melodi_radio_u8 buffer[MELODI_RADIO_PAYLOAD_MAX];
};

void melodi_radio_stream_init(struct melodi_radio_stream *stream);
int melodi_radio_stream_feed(struct melodi_radio_stream *stream,
                             melodi_radio_u8 byte,
                             const struct melodi_radio_header **header,
                             const melodi_radio_u8 **payload);
int melodi_radio_stream_encode(melodi_radio_u8 type, const void *payload,
                               size_t length, void *output, size_t capacity,
                               size_t *encoded_length);

int melodi_radio_encode_identify(void *output, size_t capacity,
                                 size_t *encoded_length);
int melodi_radio_encode_reset(void *output, size_t capacity,
                              size_t *encoded_length);
int melodi_radio_encode_configure(const struct melodi_radio_configure *config,
                                  void *output, size_t capacity,
                                  size_t *encoded_length);
int melodi_radio_encode_transmit(const struct melodi_radio_transmit *transmit,
                                 void *output, size_t capacity,
                                 size_t *encoded_length);
int melodi_radio_encode_info(const struct melodi_radio_info *info,
                             void *output, size_t capacity,
                             size_t *encoded_length);
int melodi_radio_encode_status(const struct melodi_radio_status *status,
                               void *output, size_t capacity,
                               size_t *encoded_length);
int melodi_radio_encode_receive(const struct melodi_radio_receive *receive,
                                void *output, size_t capacity,
                                size_t *encoded_length);
int melodi_radio_encode_result(
    const struct melodi_radio_result_report *report, void *output,
    size_t capacity, size_t *encoded_length);

int melodi_radio_decode_configure(const void *input, size_t length,
                                  struct melodi_radio_configure *config);
int melodi_radio_decode_transmit(const void *input, size_t length,
                                 struct melodi_radio_transmit *transmit);
int melodi_radio_decode_info(const void *input, size_t length,
                             struct melodi_radio_info *info);
int melodi_radio_decode_status(const void *input, size_t length,
                               struct melodi_radio_status *status);
int melodi_radio_decode_receive(const void *input, size_t length,
                                struct melodi_radio_receive *receive);
int melodi_radio_decode_result(const void *input, size_t length,
                               struct melodi_radio_result_report *report);

int melodi_radio_airtime_estimate(melodi_radio_u8 spreading_factor,
                                  melodi_radio_u16 bandwidth_khz,
                                  melodi_radio_u8 coding_rate,
                                  size_t payload_length,
                                  melodi_radio_u32 *duration_us);

int melodi_radio_segment_encode(const struct melodi_radio_segment *segment,
                                void *output, size_t capacity,
                                size_t *encoded_length);
int melodi_radio_segment_decode(const void *input, size_t length,
                                struct melodi_radio_segment *segment);

#ifdef __cplusplus
}
#endif

#endif
