/* SPDX-License-Identifier: GPL-2.0-only */
#include "reliability.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>

int main(void)
{
    struct melodi_reliability_state state;
    uint64_t missing = 0;

    assert(melodi_reliability_start(&state, 7, 2, 4, 1000, 0, 0) == 0);
    assert(melodi_reliability_poll(&state, 1199, false, &missing) == 0);
    assert(melodi_reliability_poll(&state, 1200, false, &missing) == 1);
    assert(missing == 0x0f && state.retries == 1);
    assert(melodi_reliability_ack(&state, 7, 2, 4, 0x05, false) == 0);
    assert(melodi_reliability_ack(&state, 7, 2, 4, 0x05, false) == 0);
    assert(melodi_reliability_poll(&state, 1700, false, &missing) == 1);
    assert(missing == 0x0a);
    assert(melodi_reliability_ack(&state, 7, 2, 4, 0x0a, false) == 1);
    assert(melodi_reliability_poll(&state, 1700, false, &missing) == -ENOENT);
    assert(melodi_reliability_start(&state, 8, 3, 64, 0, 0, 0) == 0);
    assert(melodi_reliability_ack(&state, 8, 3, 64, UINT64_MAX, false) == 1);
    assert(melodi_reliability_start(&state, 9, 4, 2, 0, 0, 0) == 0);
    assert(melodi_reliability_ack(&state, 9, 4, 2, 4, false) == -EPROTO);
    assert(melodi_reliability_ack(&state, 9, 4, 2, 1, true) ==
           -ECONNREFUSED);
    assert(melodi_reliability_start(&state, 10, 5, 1, 0, 0, 0) == 0);
    assert(melodi_reliability_poll(&state, 200, false, &missing) == 1);
    assert(melodi_reliability_poll(&state, 700, false, &missing) == 1);
    assert(melodi_reliability_poll(&state, 1700, false, &missing) == 1);
    assert(melodi_reliability_poll(&state, 3700, false, &missing) == 1);
    assert(melodi_reliability_poll(&state, 4999, false, &missing) == 0);
    assert(melodi_reliability_poll(&state, 5000, false, &missing) ==
           -ETIMEDOUT);
    assert(melodi_reliability_start(&state, 11, 6, 1, UINT64_MAX - 100, 0,
                                    0) == -EOVERFLOW);

    /* A queued message defers retries instead of duplicating fragments. */
    assert(melodi_reliability_start(&state, 12, 7, 1, 0, 0, 0) == 0);
    assert(melodi_reliability_poll(&state, 200, true, &missing) == 0);
    assert(melodi_reliability_poll(&state, 400, true, &missing) == 0);
    assert(state.retries == 0 && state.next_retry_ms == 600);
    assert(melodi_reliability_poll(&state, 599, false, &missing) == 0);
    assert(melodi_reliability_poll(&state, 600, false, &missing) == 1);

    /* Retry and deadline schedules scale with the link round trip. */
    assert(melodi_reliability_start(&state, 13, 8, 1, 0, 2400, 60000) == 0);
    assert(state.deadline_ms == 60000);
    assert(melodi_reliability_poll(&state, 4799, false, &missing) == 0);
    assert(melodi_reliability_poll(&state, 4800, false, &missing) == 1);

    /* The message TTL caps the reliability deadline. */
    assert(melodi_reliability_start(&state, 14, 9, 1, 0, 2400, 30000) == 0);
    assert(state.deadline_ms == 30000);
    return 0;
}
