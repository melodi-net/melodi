/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "usb_attach.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct fixture_file {
    const char *path;
    const char *value;
};

static const char *const directories[] = {
    "bus",
    "bus/usb",
    "bus/usb/devices",
    "bus/usb/devices/1-8.1",
    "bus/usb/devices/1-8.1:1.0",
    "bus/usb/devices/1-8.1:1.0/ep_81",
    "bus/usb/devices/1-8.1:1.1",
    "bus/usb/devices/1-8.1:1.1/ep_01",
    "bus/usb/devices/1-8.1:1.1/ep_82",
    "class",
    "class/tty",
    "class/tty/radio0",
    "module",
    "module/melodi_usb",
    "module/melodi_usb/parameters",
    "dev",
};

static const struct fixture_file files[] = {
    { "bus/usb/devices/1-8.1/idVendor", "2e8a\n" },
    { "bus/usb/devices/1-8.1/idProduct", "000a\n" },
    { "bus/usb/devices/1-8.1/bcdDevice", "0100\n" },
    { "bus/usb/devices/1-8.1/product", "Pico\n" },
    { "bus/usb/devices/1-8.1/serial", "DF643CF0134A4C26\n" },
    { "bus/usb/devices/1-8.1/speed", "12\n" },
    { "bus/usb/devices/1-8.1/bNumConfigurations", "1\n" },
    { "bus/usb/devices/1-8.1/bConfigurationValue", "1\n" },
    { "bus/usb/devices/1-8.1/bNumInterfaces", " 2\n" },
    { "bus/usb/devices/1-8.1:1.0/bInterfaceNumber", "00\n" },
    { "bus/usb/devices/1-8.1:1.0/bInterfaceClass", "02\n" },
    { "bus/usb/devices/1-8.1:1.0/bInterfaceSubClass", "02\n" },
    { "bus/usb/devices/1-8.1:1.0/bInterfaceProtocol", "00\n" },
    { "bus/usb/devices/1-8.1:1.0/bNumEndpoints", "01\n" },
    { "bus/usb/devices/1-8.1:1.0/ep_81/bEndpointAddress", "81\n" },
    { "bus/usb/devices/1-8.1:1.0/ep_81/bmAttributes", "03\n" },
    { "bus/usb/devices/1-8.1:1.0/ep_81/wMaxPacketSize", "0008\n" },
    { "bus/usb/devices/1-8.1:1.1/bInterfaceNumber", "01\n" },
    { "bus/usb/devices/1-8.1:1.1/bInterfaceClass", "0a\n" },
    { "bus/usb/devices/1-8.1:1.1/bInterfaceSubClass", "00\n" },
    { "bus/usb/devices/1-8.1:1.1/bInterfaceProtocol", "00\n" },
    { "bus/usb/devices/1-8.1:1.1/bNumEndpoints", "02\n" },
    { "bus/usb/devices/1-8.1:1.1/ep_01/bEndpointAddress", "01\n" },
    { "bus/usb/devices/1-8.1:1.1/ep_01/bmAttributes", "02\n" },
    { "bus/usb/devices/1-8.1:1.1/ep_01/wMaxPacketSize", "0040\n" },
    { "bus/usb/devices/1-8.1:1.1/ep_82/bEndpointAddress", "82\n" },
    { "bus/usb/devices/1-8.1:1.1/ep_82/bmAttributes", "02\n" },
    { "bus/usb/devices/1-8.1:1.1/ep_82/wMaxPacketSize", "0040\n" },
    { "class/tty/radio0/dev", "166:0\n" },
    { "module/melodi_usb/parameters/attach", "" },
    { "module/melodi_usb/parameters/release", "" },
};

static void fixture_path(char output[512], const char *root,
                         const char *relative)
{
    int length = snprintf(output, 512, "%s/%s", root, relative);

    assert(length > 0 && length < 512);
}

static void fixture_write(const char *root, const char *relative,
                          const char *value)
{
    char path[512];
    size_t length = strlen(value);
    int descriptor;

    fixture_path(path, root, relative);
    descriptor = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(descriptor >= 0);
    assert(write(descriptor, value, length) == (ssize_t)length);
    assert(close(descriptor) == 0);
}

static void fixture_create(const char *root)
{
    char path[512];
    size_t index;

    for (index = 0; index < sizeof(directories) / sizeof(directories[0]);
         index++) {
        fixture_path(path, root, directories[index]);
        assert(mkdir(path, 0700) == 0);
    }
    for (index = 0; index < sizeof(files) / sizeof(files[0]); index++)
        fixture_write(root, files[index].path, files[index].value);
    fixture_path(path, root, "class/tty/radio0/device");
    assert(symlink("../../../bus/usb/devices/1-8.1", path) == 0);
}

static void fixture_remove(const char *root)
{
    char path[512];
    size_t index;

    fixture_path(path, root, "class/tty/radio0/device");
    unlink(path);
    fixture_path(path, root, "dev/ttyMEL0");
    unlink(path);
    fixture_path(path, root, "dev/ttyMEL1");
    unlink(path);
    for (index = 0; index < sizeof(files) / sizeof(files[0]); index++) {
        fixture_path(path, root, files[index].path);
        assert(unlink(path) == 0);
    }
    for (index = sizeof(directories) / sizeof(directories[0]); index > 0;
         index--) {
        fixture_path(path, root, directories[index - 1]);
        assert(rmdir(path) == 0);
    }
    assert(rmdir(root) == 0);
}

int main(void)
{
    char root[] = "/tmp/melodi-usb-attach-XXXXXX";
    char serial[MELODI_RADIO_SERIAL_MAX + 1];
    char device_root[512];
    char value[32] = { 0 };
    char path[512];
    ssize_t length;
    int descriptor;

    assert(mkdtemp(root) == root);
    fixture_create(root);
    fixture_path(device_root, root, "dev");
    assert(melodi_usb_validate_device_at(root, "1-8.1", serial) == 0);
    assert(strcmp(serial, "DF643CF0134A4C26") == 0);
    assert(melodi_usb_validate_device_at(root, "../1-8.1", serial) ==
           -EINVAL);
    assert(melodi_tty_attach_serial_at(root, device_root, 0,
                                       "DF643CF0133C4826") == -ENOENT);
    assert(melodi_tty_attach_serial_at(root, device_root, MELODI_TTY_LIMIT,
                                       "DF643CF0134A4C26") == -ERANGE);
    fixture_write(root, "bus/usb/devices/1-8.1/product", "Other\n");
    assert(melodi_usb_validate_device_at(root, "1-8.1", serial) == -ENODEV);
    fixture_write(root, "bus/usb/devices/1-8.1/product", "Pico\n");
    assert(melodi_tty_attach_serial_at(root, device_root, 0,
                                       "DF643CF0134A4C26") == 0);
    fixture_path(path, root, "dev/ttyMEL0");
    length = readlink(path, value, sizeof(value) - 1);
    assert(length == 6);
    value[length] = '\0';
    assert(strcmp(value, "radio0") == 0);
    fixture_path(path, root, "module/melodi_usb/parameters/attach");
    descriptor = open(path, O_RDONLY);
    assert(descriptor >= 0);
    memset(value, 0, sizeof(value));
    assert(read(descriptor, value, sizeof(value) - 1) == 5);
    assert(close(descriptor) == 0);
    assert(strcmp(value, "166:0") == 0);
    assert(melodi_tty_release_at(root, device_root, 0) == 0);
    fixture_path(path, root, "dev/ttyMEL0");
    assert(access(path, F_OK) < 0 && errno == ENOENT);
    fixture_path(path, root, "module/melodi_usb/parameters/release");
    descriptor = open(path, O_RDONLY);
    assert(descriptor >= 0);
    memset(value, 0, sizeof(value));
    assert(read(descriptor, value, sizeof(value) - 1) == 5);
    assert(close(descriptor) == 0);
    assert(strcmp(value, "166:0") == 0);
    fixture_path(path, root, "dev/ttyMEL1");
    fixture_write(root, "dev/ttyMEL1", "occupied");
    assert(melodi_tty_attach_serial_at(root, device_root, 1,
                                       "DF643CF0134A4C26") == -EEXIST);
    assert(unlink(path) == 0);
    fixture_remove(root);
    return 0;
}
