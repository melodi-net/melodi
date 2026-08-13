/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MELODI_RELIABILITY_H
#define MELODI_RELIABILITY_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef u8 melodi_reliable_u8;
typedef u16 melodi_reliable_u16;
typedef u32 melodi_reliable_u32;
typedef u64 melodi_reliable_u64;
#else
#include <stdbool.h>
#include <stdint.h>
typedef uint8_t melodi_reliable_u8;
typedef uint16_t melodi_reliable_u16;
typedef uint32_t melodi_reliable_u32;
typedef uint64_t melodi_reliable_u64;
#endif

#define MELODI_RELIABLE_RETRY_LIMIT 4
#define MELODI_RELIABLE_DEADLINE_MS 5000

struct melodi_reliability_state {
    melodi_reliable_u64 message_id;
    melodi_reliable_u64 acknowledged;
    melodi_reliable_u64 deadline_ms;
    melodi_reliable_u64 next_retry_ms;
    melodi_reliable_u32 generation;
    melodi_reliable_u16 fragment_count;
    melodi_reliable_u8 retries;
    bool active;
};

int melodi_reliability_start(struct melodi_reliability_state *state,
                             melodi_reliable_u64 message_id,
                             melodi_reliable_u32 generation,
                             melodi_reliable_u16 fragment_count,
                             melodi_reliable_u64 now_ms);
int melodi_reliability_ack(struct melodi_reliability_state *state,
                           melodi_reliable_u64 message_id,
                           melodi_reliable_u32 generation,
                           melodi_reliable_u16 fragment_count,
                           melodi_reliable_u64 bitmap,
                           bool rejected);
int melodi_reliability_poll(struct melodi_reliability_state *state,
                            melodi_reliable_u64 now_ms,
                            melodi_reliable_u64 *missing);

#endif
