/* SPDX-License-Identifier: GPL-2.0-only */
#include "replay.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

void melodi_replay_reset(struct melodi_replay_window *window)
{
    if (window)
        memset(window, 0, sizeof(*window));
}

bool melodi_replay_seen(const struct melodi_replay_window *window,
                        melodi_replay_u64 counter)
{
    melodi_replay_u64 distance;

    if (!window || !counter)
        return true;
    if (counter > window->highest)
        return false;
    distance = window->highest - counter;
    return distance >= MELODI_REPLAY_WINDOW_BITS ||
           window->bitmap & ((melodi_replay_u64)1 << distance);
}

int melodi_replay_mark(struct melodi_replay_window *window,
                       melodi_replay_u64 counter)
{
    melodi_replay_u64 distance;

    if (!window || !counter)
        return -EINVAL;
    if (counter > window->highest) {
        distance = counter - window->highest;
        window->bitmap = distance >= MELODI_REPLAY_WINDOW_BITS ? 1 :
                         (window->bitmap << distance) | 1;
        window->highest = counter;
        return 0;
    }
    distance = window->highest - counter;
    if (distance >= MELODI_REPLAY_WINDOW_BITS ||
        window->bitmap & ((melodi_replay_u64)1 << distance))
        return -EALREADY;
    window->bitmap |= (melodi_replay_u64)1 << distance;
    return 0;
}
