/* SPDX-License-Identifier: GPL-2.0-only */
#include "reliability.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#define MELODI_RELIABLE_U64_MAX U64_MAX
#else
#include <errno.h>
#include <string.h>
#define MELODI_RELIABLE_U64_MAX UINT64_MAX
#endif

static const melodi_reliable_u16 melodi_retry_delays[] = {
    200, 500, 1000, 2000,
};

static melodi_reliable_u64 melodi_reliability_mask(
    melodi_reliable_u16 fragment_count)
{
    return fragment_count == 64 ? MELODI_RELIABLE_U64_MAX :
           ((melodi_reliable_u64)1 << fragment_count) - 1;
}

static int melodi_reliability_add(melodi_reliable_u64 value,
                                  melodi_reliable_u64 amount,
                                  melodi_reliable_u64 *result)
{
    if (value > MELODI_RELIABLE_U64_MAX - amount)
        return -EOVERFLOW;
    *result = value + amount;
    return 0;
}

/* Scales a nominal delay to the link round trip reported by the transport. */
static melodi_reliable_u64 melodi_reliability_scale(
    melodi_reliable_u32 pace_ms, melodi_reliable_u64 nominal_ms)
{
    if (pace_ms < MELODI_RELIABLE_PACE_BASE_MS)
        pace_ms = MELODI_RELIABLE_PACE_BASE_MS;
    if (pace_ms > MELODI_RELIABLE_PACE_LIMIT_MS)
        pace_ms = MELODI_RELIABLE_PACE_LIMIT_MS;
    return nominal_ms * pace_ms / MELODI_RELIABLE_PACE_BASE_MS;
}

static melodi_reliable_u64 melodi_reliability_delay(
    const struct melodi_reliability_state *state)
{
    melodi_reliable_u8 index = state->retries;

    if (index >= MELODI_RELIABLE_RETRY_LIMIT)
        index = MELODI_RELIABLE_RETRY_LIMIT - 1;
    return melodi_reliability_scale(state->pace_ms,
                                    melodi_retry_delays[index]);
}

int melodi_reliability_start(struct melodi_reliability_state *state,
                             melodi_reliable_u64 message_id,
                             melodi_reliable_u32 generation,
                             melodi_reliable_u16 fragment_count,
                             melodi_reliable_u64 now_ms,
                             melodi_reliable_u32 pace_ms,
                             melodi_reliable_u32 ttl_ms)
{
    melodi_reliable_u64 deadline;
    int error;

    if (!state || !message_id || !generation || !fragment_count ||
        fragment_count > 64)
        return -EINVAL;
    memset(state, 0, sizeof(*state));
    state->pace_ms = pace_ms;
    deadline = melodi_reliability_scale(pace_ms, MELODI_RELIABLE_DEADLINE_MS);
    if (ttl_ms && deadline > ttl_ms)
        deadline = ttl_ms;
    error = melodi_reliability_add(now_ms, deadline, &state->deadline_ms);
    if (!error)
        error = melodi_reliability_add(
            now_ms, melodi_reliability_scale(pace_ms, melodi_retry_delays[0]),
            &state->next_retry_ms);
    if (error) {
        memset(state, 0, sizeof(*state));
        return error;
    }
    state->message_id = message_id;
    state->generation = generation;
    state->fragment_count = fragment_count;
    state->active = true;
    return 0;
}

int melodi_reliability_ack(struct melodi_reliability_state *state,
                           melodi_reliable_u64 message_id,
                           melodi_reliable_u32 generation,
                           melodi_reliable_u16 fragment_count,
                           melodi_reliable_u64 bitmap,
                           bool rejected)
{
    melodi_reliable_u64 expected;

    if (!state || !state->active || state->message_id != message_id ||
        state->generation != generation ||
        state->fragment_count != fragment_count)
        return -ENOENT;
    expected = melodi_reliability_mask(fragment_count);
    if (!bitmap || bitmap & ~expected)
        return -EPROTO;
    state->acknowledged |= bitmap;
    if (rejected) {
        state->active = false;
        return -ECONNREFUSED;
    }
    if (state->acknowledged == expected) {
        state->active = false;
        return 1;
    }
    return 0;
}

int melodi_reliability_poll(struct melodi_reliability_state *state,
                            melodi_reliable_u64 now_ms,
                            bool queued,
                            melodi_reliable_u64 *missing)
{
    melodi_reliable_u64 expected;
    int error;

    if (!state || !missing || !state->active)
        return -ENOENT;
    if (now_ms >= state->deadline_ms) {
        state->active = false;
        return -ETIMEDOUT;
    }
    /* Fragments still awaiting transmission cannot be lost yet. */
    if (queued)
        return melodi_reliability_add(now_ms, melodi_reliability_delay(state),
                                      &state->next_retry_ms);
    if (now_ms < state->next_retry_ms)
        return 0;
    if (state->retries >= MELODI_RELIABLE_RETRY_LIMIT) {
        state->active = false;
        return -ETIMEDOUT;
    }
    expected = melodi_reliability_mask(state->fragment_count);
    *missing = expected & ~state->acknowledged;
    state->retries++;
    if (state->retries == MELODI_RELIABLE_RETRY_LIMIT) {
        state->next_retry_ms = state->deadline_ms;
        return 1;
    }
    error = melodi_reliability_add(now_ms, melodi_reliability_delay(state),
                                   &state->next_retry_ms);
    if (error) {
        state->active = false;
        return error;
    }
    return 1;
}

#undef MELODI_RELIABLE_U64_MAX
