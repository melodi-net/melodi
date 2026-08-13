/* SPDX-License-Identifier: GPL-2.0-only */
#include "airtime.h"

#include <assert.h>
#include <errno.h>

int main(void)
{
    struct melodi_airtime_window window = { 0 };
    uint64_t wait_ms;

    assert(melodi_airtime_admit(&window, 0, 100, 40, &wait_ms) == 0);
    assert(melodi_airtime_admit(&window, 0, 100, 40, &wait_ms) == 0);
    assert(window.total_us == 80);
    assert(melodi_airtime_admit(&window, 0, 100, 30, &wait_ms) ==
           -EAGAIN);
    assert(wait_ms == 3600000);
    assert(window.total_us == 80);
    assert(melodi_airtime_admit(&window, 3599999, 100, 30,
                                &wait_ms) == -EAGAIN);
    assert(wait_ms == 1);
    assert(melodi_airtime_admit(&window, 3600000, 100, 30,
                                &wait_ms) == 0);
    assert(window.total_us == 30);

    melodi_airtime_reset(&window);
    assert(melodi_airtime_admit(&window, 0, 100, 60, &wait_ms) == 0);
    assert(melodi_airtime_admit(&window, 60000, 100, 40, &wait_ms) == 0);
    assert(melodi_airtime_admit(&window, 60000, 100, 20, &wait_ms) ==
           -EAGAIN);
    assert(wait_ms == 3540000);
    assert(melodi_airtime_admit(&window, 3600000, 100, 20,
                                &wait_ms) == 0);
    assert(window.total_us == 60);

    assert(melodi_airtime_admit(&window, 3600000, 10, 11, &wait_ms) ==
           -EMSGSIZE);
    assert(melodi_airtime_admit(NULL, 0, 10, 1, &wait_ms) == -EINVAL);
    assert(melodi_airtime_admit(&window, 0, 0, 1, &wait_ms) == -EINVAL);
    assert(melodi_airtime_admit(&window, 0, 10, 0, &wait_ms) == -EINVAL);
    assert(melodi_airtime_admit(&window, 0, 10, 1, NULL) == -EINVAL);
    return 0;
}
