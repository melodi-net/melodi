/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MELODI_ORDERING_H
#define MELODI_ORDERING_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef u8 melodi_order_u8;
typedef u32 melodi_order_u32;
typedef u64 melodi_order_u64;
#else
#include <stdbool.h>
#include <stdint.h>
typedef uint8_t melodi_order_u8;
typedef uint32_t melodi_order_u32;
typedef uint64_t melodi_order_u64;
#endif

#define MELODI_ORDER_WINDOW 32
#define MELODI_ORDER_GAP_MS 5000

enum melodi_order_result {
    MELODI_ORDER_HELD,
    MELODI_ORDER_RELEASED,
    MELODI_ORDER_DUPLICATE,
};

struct melodi_order_state {
    melodi_order_u64 deadline_ms;
    melodi_order_u32 expected;
    melodi_order_u32 pending;
};

void melodi_order_reset(struct melodi_order_state *state);
melodi_order_u32 melodi_order_next(melodi_order_u32 marker);
int melodi_order_admit(struct melodi_order_state *state,
                       melodi_order_u32 marker, melodi_order_u64 now_ms,
                       melodi_order_u32 *release_marker,
                       melodi_order_u8 *release_count);
int melodi_order_poll(struct melodi_order_state *state,
                      melodi_order_u64 now_ms,
                      melodi_order_u32 *release_marker,
                      melodi_order_u8 *release_count);

#endif
