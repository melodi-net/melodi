/* SPDX-License-Identifier: GPL-2.0-only */
#include "reliability.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>

int main(void)
{
    struct melodi_reliability_state state;
    uint64_t missing = 0;

    assert(melodi_reliability_start(&state, 7, 2, 4, 1000) == 0);
    assert(melodi_reliability_poll(&state, 1199, &missing) == 0);
    assert(melodi_reliability_poll(&state, 1200, &missing) == 1);
    assert(missing == 0x0f && state.retries == 1);
    assert(melodi_reliability_ack(&state, 7, 2, 4, 0x05, false) == 0);
    assert(melodi_reliability_ack(&state, 7, 2, 4, 0x05, false) == 0);
    assert(melodi_reliability_poll(&state, 1700, &missing) == 1);
    assert(missing == 0x0a);
    assert(melodi_reliability_ack(&state, 7, 2, 4, 0x0a, false) == 1);
    assert(melodi_reliability_poll(&state, 1700, &missing) == -ENOENT);
    assert(melodi_reliability_start(&state, 8, 3, 64, 0) == 0);
    assert(melodi_reliability_ack(&state, 8, 3, 64, UINT64_MAX, false) == 1);
    assert(melodi_reliability_start(&state, 9, 4, 2, 0) == 0);
    assert(melodi_reliability_ack(&state, 9, 4, 2, 4, false) == -EPROTO);
    assert(melodi_reliability_ack(&state, 9, 4, 2, 1, true) ==
           -ECONNREFUSED);
    assert(melodi_reliability_start(&state, 10, 5, 1, 0) == 0);
    assert(melodi_reliability_poll(&state, 200, &missing) == 1);
    assert(melodi_reliability_poll(&state, 700, &missing) == 1);
    assert(melodi_reliability_poll(&state, 1700, &missing) == 1);
    assert(melodi_reliability_poll(&state, 3700, &missing) == 1);
    assert(melodi_reliability_poll(&state, 4999, &missing) == 0);
    assert(melodi_reliability_poll(&state, 5000, &missing) == -ETIMEDOUT);
    assert(melodi_reliability_start(&state, 11, 6, 1,
                                    UINT64_MAX - 100) == -EOVERFLOW);
    return 0;
}
