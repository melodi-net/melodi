/* SPDX-License-Identifier: GPL-2.0-only */
#include "replay.h"

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

int main(void)
{
    struct melodi_replay_window window;

    melodi_replay_reset(&window);
    assert(window.highest == 0 && window.bitmap == 0);
    assert(!melodi_replay_seen(&window, 1));
    assert(melodi_replay_mark(&window, 1) == 0);
    assert(melodi_replay_seen(&window, 1));
    assert(melodi_replay_mark(&window, 1) == -EALREADY);
    assert(melodi_replay_mark(&window, 4) == 0);
    assert(window.highest == 4 && window.bitmap == 9);
    assert(!melodi_replay_seen(&window, 3));
    assert(melodi_replay_mark(&window, 3) == 0);
    assert(melodi_replay_seen(&window, 3));
    assert(melodi_replay_mark(&window, 68) == 0);
    assert(window.highest == 68 && window.bitmap == 1);
    assert(!melodi_replay_seen(&window, 5));
    assert(melodi_replay_seen(&window, 4));
    assert(melodi_replay_mark(&window, 5) == 0);
    assert(melodi_replay_mark(&window, 4) == -EALREADY);
    assert(melodi_replay_mark(&window, UINT64_MAX) == 0);
    assert(melodi_replay_seen(&window, UINT64_MAX));
    assert(melodi_replay_mark(&window, UINT64_MAX) == -EALREADY);
    assert(melodi_replay_seen(&window, 0));
    assert(melodi_replay_seen(NULL, 1));
    assert(melodi_replay_mark(&window, 0) == -EINVAL);
    assert(melodi_replay_mark(NULL, 1) == -EINVAL);
    melodi_replay_reset(&window);
    assert(!melodi_replay_seen(&window, UINT64_MAX));
    return 0;
}
