/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MELODI_AIRTIME_H
#define MELODI_AIRTIME_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef u32 melodi_airtime_u32;
typedef u64 melodi_airtime_u64;
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef uint32_t melodi_airtime_u32;
typedef uint64_t melodi_airtime_u64;
#endif

#define MELODI_AIRTIME_BUCKETS 360
#define MELODI_AIRTIME_SLOT_MS 10000ULL
#ifndef MELODI_AIRTIME_WINDOW_US
#define MELODI_AIRTIME_WINDOW_US 3600000000ULL
#endif

struct melodi_airtime_window {
    melodi_airtime_u32 buckets[MELODI_AIRTIME_BUCKETS];
    melodi_airtime_u64 epoch_slot;
    melodi_airtime_u64 total_us;
    bool initialized;
};

void melodi_airtime_reset(struct melodi_airtime_window *window);
int melodi_airtime_admit(struct melodi_airtime_window *window,
                         melodi_airtime_u64 now_ms,
                         melodi_airtime_u64 budget_us,
                         melodi_airtime_u64 cost_us,
                         melodi_airtime_u64 *wait_ms);

#endif
