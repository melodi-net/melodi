/* SPDX-License-Identifier: GPL-2.0-only */
#include "ordering.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#define MELODI_ORDER_U32_MAX U32_MAX
#define MELODI_ORDER_U64_MAX U64_MAX
#else
#include <errno.h>
#include <string.h>
#define MELODI_ORDER_U32_MAX UINT32_MAX
#define MELODI_ORDER_U64_MAX UINT64_MAX
#endif

#define MELODI_ORDER_MODULUS 0xffffffffULL

static int melodi_order_deadline(melodi_order_u64 now_ms,
                                 melodi_order_u64 *deadline_ms)
{
    if (now_ms > MELODI_ORDER_U64_MAX - MELODI_ORDER_GAP_MS)
        return -EOVERFLOW;
    *deadline_ms = now_ms + MELODI_ORDER_GAP_MS;
    return 0;
}

static melodi_order_u32 melodi_order_advance(melodi_order_u32 marker,
                                             melodi_order_u8 count)
{
    while (count--)
        marker = melodi_order_next(marker);
    return marker;
}

static int melodi_order_distance(melodi_order_u32 expected,
                                 melodi_order_u32 marker,
                                 melodi_order_u32 *forward)
{
    melodi_order_u64 expected_index;
    melodi_order_u64 marker_index;
    melodi_order_u64 distance;

    if (!expected || !marker || !forward)
        return -EINVAL;
    expected_index = (melodi_order_u64)expected - 1;
    marker_index = (melodi_order_u64)marker - 1;
    distance = marker_index >= expected_index ?
        marker_index - expected_index :
        MELODI_ORDER_MODULUS - (expected_index - marker_index);
    *forward = distance;
    return 0;
}

static void melodi_order_release(struct melodi_order_state *state,
                                 melodi_order_u32 marker,
                                 melodi_order_u32 bits,
                                 melodi_order_u32 *release_marker,
                                 melodi_order_u8 *release_count)
{
    melodi_order_u8 count = 1;

    state->expected = melodi_order_next(marker);
    while (bits & 1U) {
        bits >>= 1;
        state->expected = melodi_order_next(state->expected);
        count++;
    }
    state->pending = bits >> 1;
    if (!state->pending)
        state->deadline_ms = 0;
    *release_marker = marker;
    *release_count = count;
}

void melodi_order_reset(struct melodi_order_state *state)
{
    if (!state)
        return;
    memset(state, 0, sizeof(*state));
    state->expected = 1;
}

melodi_order_u32 melodi_order_next(melodi_order_u32 marker)
{
    return marker == MELODI_ORDER_U32_MAX ? 1 : marker + 1;
}

int melodi_order_admit(struct melodi_order_state *state,
                       melodi_order_u32 marker, melodi_order_u64 now_ms,
                       melodi_order_u32 *release_marker,
                       melodi_order_u8 *release_count)
{
    melodi_order_u32 forward;
    melodi_order_u32 backward;
    melodi_order_u32 bit;
    int error;

    if (!state || !release_marker || !release_count || !state->expected)
        return -EINVAL;
    *release_marker = 0;
    *release_count = 0;
    error = melodi_order_distance(state->expected, marker, &forward);
    if (error)
        return error;
    if (!forward) {
        melodi_order_release(state, marker, state->pending,
                             release_marker, release_count);
        return MELODI_ORDER_RELEASED;
    }
    if (forward <= MELODI_ORDER_WINDOW) {
        bit = 1U << (forward - 1);
        if (state->pending & bit)
            return MELODI_ORDER_DUPLICATE;
        if (!state->deadline_ms) {
            error = melodi_order_deadline(now_ms, &state->deadline_ms);
            if (error)
                return error;
        }
        state->pending |= bit;
        return MELODI_ORDER_HELD;
    }
    backward = MELODI_ORDER_MODULUS - forward;
    return backward <= MELODI_ORDER_WINDOW ? MELODI_ORDER_DUPLICATE :
                                             -ERANGE;
}

int melodi_order_poll(struct melodi_order_state *state,
                      melodi_order_u64 now_ms,
                      melodi_order_u32 *release_marker,
                      melodi_order_u8 *release_count)
{
    melodi_order_u32 bits;
    melodi_order_u8 skipped = 0;
    melodi_order_u32 marker;
    int error;

    if (!state || !release_marker || !release_count || !state->expected)
        return -EINVAL;
    *release_marker = 0;
    *release_count = 0;
    if (!state->pending || now_ms < state->deadline_ms)
        return MELODI_ORDER_HELD;
    bits = state->pending;
    while (!(bits & 1U)) {
        bits >>= 1;
        skipped++;
    }
    marker = melodi_order_advance(state->expected, skipped + 1);
    bits >>= 1;
    melodi_order_release(state, marker, bits, release_marker, release_count);
    if (!state->pending)
        return MELODI_ORDER_RELEASED;
    error = melodi_order_deadline(now_ms, &state->deadline_ms);
    return error ? error : MELODI_ORDER_RELEASED;
}

#undef MELODI_ORDER_U64_MAX
#undef MELODI_ORDER_U32_MAX
