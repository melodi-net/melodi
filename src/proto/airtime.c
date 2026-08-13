/* SPDX-License-Identifier: GPL-2.0-only */
#include "airtime.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

static void melodi_airtime_advance(struct melodi_airtime_window *window,
                                   melodi_airtime_u64 slot)
{
    melodi_airtime_u64 elapsed;
    unsigned int index;

    if (!window->initialized || slot < window->epoch_slot) {
        memset(window, 0, sizeof(*window));
        window->epoch_slot = slot;
        window->initialized = true;
        return;
    }
    elapsed = slot - window->epoch_slot;
    if (elapsed >= MELODI_AIRTIME_BUCKETS) {
        memset(window->buckets, 0, sizeof(window->buckets));
        window->total_us = 0;
    } else {
        for (index = 1; index <= elapsed; index++) {
            unsigned int expired =
                (window->epoch_slot + index) % MELODI_AIRTIME_BUCKETS;

            window->total_us -= window->buckets[expired];
            window->buckets[expired] = 0;
        }
    }
    window->epoch_slot = slot;
}

void melodi_airtime_reset(struct melodi_airtime_window *window)
{
    if (window)
        memset(window, 0, sizeof(*window));
}

int melodi_airtime_admit(struct melodi_airtime_window *window,
                         melodi_airtime_u64 now_ms,
                         melodi_airtime_u64 budget_us,
                         melodi_airtime_u64 cost_us,
                         melodi_airtime_u64 *wait_ms)
{
    melodi_airtime_u64 remaining;
    melodi_airtime_u64 slot;
    unsigned int index;

    if (!window || !wait_ms || !budget_us || !cost_us ||
        budget_us > MELODI_AIRTIME_WINDOW_US)
        return -EINVAL;
    *wait_ms = 0;
    if (cost_us > budget_us)
        return -EMSGSIZE;
    slot = now_ms / MELODI_AIRTIME_SLOT_MS;
    melodi_airtime_advance(window, slot);
    if (window->total_us <= budget_us - cost_us) {
        index = slot % MELODI_AIRTIME_BUCKETS;
        window->buckets[index] += (melodi_airtime_u32)cost_us;
        window->total_us += cost_us;
        return 0;
    }
    remaining = window->total_us;
    for (index = 1; index <= MELODI_AIRTIME_BUCKETS; index++) {
        unsigned int expired =
            (slot + index) % MELODI_AIRTIME_BUCKETS;

        remaining -= window->buckets[expired];
        if (remaining <= budget_us - cost_us) {
            *wait_ms = (melodi_airtime_u64)index *
                       MELODI_AIRTIME_SLOT_MS -
                       now_ms % MELODI_AIRTIME_SLOT_MS;
            return -EAGAIN;
        }
    }
    return -EOVERFLOW;
}
