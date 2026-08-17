/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MELODI_USB_ATTACH_H
#define MELODI_USB_ATTACH_H

#include "melodi.h"

#define MELODI_USB_DEVICE_NAME_MAX 63
#define MELODI_TTY_LIMIT 16

int melodi_usb_validate_device_at(
    const char *sysfs_root, const char *device_name,
    char serial[MELODI_RADIO_SERIAL_MAX + 1]);
int melodi_tty_attach_serial_at(const char *sysfs_root,
                                const char *device_root,
                                unsigned int interface_index,
                                const char *expected_serial);
int melodi_tty_release_at(const char *sysfs_root, const char *device_root,
                          unsigned int interface_index);
int melodi_tty_release_all_at(const char *sysfs_root);

#endif
