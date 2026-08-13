/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MELODI_REPLAY_H
#define MELODI_REPLAY_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef u64 melodi_replay_u64;
#else
#include <stdbool.h>
#include <stdint.h>
typedef uint64_t melodi_replay_u64;
#endif

#define MELODI_REPLAY_WINDOW_BITS 64

struct melodi_replay_window {
    melodi_replay_u64 highest;
    melodi_replay_u64 bitmap;
};

void melodi_replay_reset(struct melodi_replay_window *window);
bool melodi_replay_seen(const struct melodi_replay_window *window,
                        melodi_replay_u64 counter);
int melodi_replay_mark(struct melodi_replay_window *window,
                       melodi_replay_u64 counter);

#endif
