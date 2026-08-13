/* SPDX-License-Identifier: GPL-2.0-only */
#include "ordering.h"

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

int main(void)
{
    struct melodi_order_state state;
    uint32_t marker = 0;
    uint8_t count = 0;

    melodi_order_reset(&state);
    assert(state.expected == 1);
    assert(melodi_order_admit(&state, 3, 0, &marker, &count) ==
           MELODI_ORDER_HELD);
    assert(melodi_order_admit(&state, 2, 1, &marker, &count) ==
           MELODI_ORDER_HELD);
    assert(melodi_order_admit(&state, 2, 2, &marker, &count) ==
           MELODI_ORDER_DUPLICATE);
    assert(melodi_order_admit(&state, 1, 3, &marker, &count) ==
           MELODI_ORDER_RELEASED);
    assert(marker == 1 && count == 3 && state.expected == 4);
    assert(melodi_order_admit(&state, 3, 4, &marker, &count) ==
           MELODI_ORDER_DUPLICATE);
    assert(melodi_order_admit(&state, 37, 5, &marker, &count) == -ERANGE);

    melodi_order_reset(&state);
    assert(melodi_order_admit(&state, 2, 0, &marker, &count) ==
           MELODI_ORDER_HELD);
    assert(melodi_order_admit(&state, 4, 1, &marker, &count) ==
           MELODI_ORDER_HELD);
    assert(melodi_order_poll(&state, 4999, &marker, &count) ==
           MELODI_ORDER_HELD);
    assert(melodi_order_poll(&state, 5000, &marker, &count) ==
           MELODI_ORDER_RELEASED);
    assert(marker == 2 && count == 1 && state.expected == 3);
    assert(melodi_order_poll(&state, 9999, &marker, &count) ==
           MELODI_ORDER_HELD);
    assert(melodi_order_poll(&state, 10000, &marker, &count) ==
           MELODI_ORDER_RELEASED);
    assert(marker == 4 && count == 1 && state.expected == 5);

    melodi_order_reset(&state);
    state.expected = UINT32_MAX;
    assert(melodi_order_admit(&state, 1, 0, &marker, &count) ==
           MELODI_ORDER_HELD);
    assert(melodi_order_admit(&state, UINT32_MAX, 1, &marker, &count) ==
           MELODI_ORDER_RELEASED);
    assert(marker == UINT32_MAX && count == 2 && state.expected == 2);
    assert(melodi_order_next(UINT32_MAX) == 1);

    melodi_order_reset(&state);
    assert(melodi_order_admit(&state, 2, UINT64_MAX - 100,
                              &marker, &count) == -EOVERFLOW);
    assert(state.pending == 0 && state.deadline_ms == 0);
    assert(melodi_order_admit(NULL, 1, 0, &marker, &count) == -EINVAL);
    assert(melodi_order_admit(&state, 0, 0, &marker, &count) == -EINVAL);
    return 0;
}
