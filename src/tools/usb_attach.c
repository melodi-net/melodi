/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "usb_attach.h"

#include "contract.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MELODI_SYSFS_PATH_MAX 512
#define MELODI_SYSFS_VALUE_MAX 80
#define MELODI_TTY_NAME_MAX 63

static int melodi_usb_attr_path(char path[MELODI_SYSFS_PATH_MAX],
                                const char *root, const char *name,
                                const char *attribute)
{
    int length;

    if (!root || root[0] != '/' || !name || !attribute)
        return -EINVAL;
    length = snprintf(path, MELODI_SYSFS_PATH_MAX,
                      "%s/bus/usb/devices/%s/%s", root, name, attribute);
    return length < 0 || length >= MELODI_SYSFS_PATH_MAX ?
           -ENAMETOOLONG : 0;
}

static int melodi_usb_read(const char *path, char *value, size_t capacity)
{
    ssize_t length;
    int descriptor;

    if (!path || !value || capacity < 2)
        return -EINVAL;
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        return -errno;
    length = read(descriptor, value, capacity);
    if (close(descriptor) < 0 && length >= 0)
        return -errno;
    if (length <= 0)
        return length < 0 ? -errno : -EINVAL;
    if ((size_t)length == capacity)
        return -E2BIG;
    while (length > 0 && isspace((unsigned char)value[length - 1]))
        length--;
    value[length] = '\0';
    return length ? 0 : -EINVAL;
}

static int melodi_usb_read_attr(const char *root, const char *name,
                                const char *attribute, char *value,
                                size_t capacity)
{
    char path[MELODI_SYSFS_PATH_MAX];
    int error;

    error = melodi_usb_attr_path(path, root, name, attribute);
    return error ? error : melodi_usb_read(path, value, capacity);
}

static int melodi_usb_number(const char *root, const char *name,
                             const char *attribute, unsigned int base,
                             unsigned int *number)
{
    char value[MELODI_SYSFS_VALUE_MAX];
    unsigned long parsed;
    char *end;
    int error;

    error = melodi_usb_read_attr(root, name, attribute, value,
                                 sizeof(value));
    if (error)
        return error;
    errno = 0;
    parsed = strtoul(value, &end, base);
    while (isspace((unsigned char)*end))
        end++;
    if (errno || end == value || *end || parsed > UINT_MAX)
        return -EINVAL;
    *number = parsed;
    return 0;
}

static int melodi_usb_expected_number(const char *root, const char *name,
                                      const char *attribute,
                                      unsigned int base,
                                      unsigned int expected)
{
    unsigned int number;
    int error;

    error = melodi_usb_number(root, name, attribute, base, &number);
    return error ? error : number == expected ? 0 : -ENODEV;
}

static bool melodi_usb_device_name_valid(const char *name)
{
    size_t length;
    size_t index;
    bool hyphen = false;

    if (!name)
        return false;
    length = strnlen(name, MELODI_USB_DEVICE_NAME_MAX + 1);
    if (!length || length > MELODI_USB_DEVICE_NAME_MAX ||
        !isdigit((unsigned char)name[0]))
        return false;
    for (index = 0; index < length; index++) {
        if (name[index] == '-') {
            if (hyphen || !index || index + 1 == length)
                return false;
            hyphen = true;
        } else if (name[index] == '.') {
            if (!index || index + 1 == length || name[index - 1] == '.' ||
                name[index - 1] == '-')
                return false;
        } else if (!isdigit((unsigned char)name[index])) {
            return false;
        }
    }
    return hyphen;
}

static bool melodi_usb_serial_valid(const char *serial)
{
    size_t length;
    size_t index;

    if (!serial)
        return false;
    length = strnlen(serial, MELODI_RADIO_SERIAL_MAX + 1);
    if (!length || length > MELODI_RADIO_SERIAL_MAX)
        return false;
    for (index = 0; index < length; index++)
        if (serial[index] < 0x21 || serial[index] > 0x7e ||
            serial[index] == ',' || serial[index] == '/')
            return false;
    return true;
}

static int melodi_usb_interface_name(char output[MELODI_USB_DEVICE_NAME_MAX + 8],
                                     const char *device_name,
                                     unsigned int interface_number)
{
    int length = snprintf(output, MELODI_USB_DEVICE_NAME_MAX + 8,
                          "%s:1.%u", device_name, interface_number);

    return length < 0 || length >= MELODI_USB_DEVICE_NAME_MAX + 8 ?
           -ENAMETOOLONG : 0;
}

static int melodi_usb_validate_endpoint(const char *root,
                                        const char *interface_name,
                                        const char *directory,
                                        unsigned int address,
                                        unsigned int attributes,
                                        unsigned int max_packet)
{
    char endpoint[MELODI_USB_DEVICE_NAME_MAX + 16];
    int length;
    int error;

    length = snprintf(endpoint, sizeof(endpoint), "%s/%s",
                      interface_name, directory);
    if (length < 0 || (size_t)length >= sizeof(endpoint))
        return -ENAMETOOLONG;
    error = melodi_usb_expected_number(root, endpoint, "bEndpointAddress",
                                       16, address);
    if (!error)
        error = melodi_usb_expected_number(root, endpoint, "bmAttributes",
                                           16, attributes);
    if (!error)
        error = melodi_usb_expected_number(root, endpoint, "wMaxPacketSize",
                                           16, max_packet);
    return error;
}

static int melodi_usb_validate_control(const char *root,
                                       const char *interface_name)
{
    int error;

    error = melodi_usb_expected_number(root, interface_name,
                                       "bInterfaceNumber", 16,
                                       MELODI_USB_PICO_CONTROL_INTERFACE);
    if (!error)
        error = melodi_usb_expected_number(root, interface_name,
                                           "bInterfaceClass", 16,
                                           MELODI_USB_PICO_CONTROL_CLASS);
    if (!error)
        error = melodi_usb_expected_number(root, interface_name,
                                           "bInterfaceSubClass", 16,
                                           MELODI_USB_PICO_CONTROL_SUBCLASS);
    if (!error)
        error = melodi_usb_expected_number(root, interface_name,
                                           "bInterfaceProtocol", 16,
                                           MELODI_USB_PICO_CONTROL_PROTOCOL);
    if (!error)
        error = melodi_usb_expected_number(root, interface_name,
                                           "bNumEndpoints", 10, 1);
    if (!error)
        error = melodi_usb_validate_endpoint(root, interface_name, "ep_81",
                                             MELODI_USB_PICO_CONTROL_IN, 3,
                                             MELODI_USB_PICO_CONTROL_MAX_PACKET);
    return error;
}

static int melodi_usb_validate_data(const char *root,
                                    const char *interface_name,
                                    struct melodi_usb_contract *contract)
{
    int error;

    error = melodi_usb_expected_number(root, interface_name,
                                       "bInterfaceNumber", 16, 1);
    if (!error)
        error = melodi_usb_expected_number(root, interface_name,
                                           "bInterfaceClass", 16, 0x0a);
    if (!error)
        error = melodi_usb_expected_number(root, interface_name,
                                           "bInterfaceSubClass", 16, 0);
    if (!error)
        error = melodi_usb_expected_number(root, interface_name,
                                           "bInterfaceProtocol", 16, 0);
    if (!error)
        error = melodi_usb_expected_number(root, interface_name,
                                           "bNumEndpoints", 10, 2);
    if (!error)
        error = melodi_usb_validate_endpoint(root, interface_name, "ep_01",
                                             1, 2, 64);
    if (!error)
        error = melodi_usb_validate_endpoint(root, interface_name, "ep_82",
                                             0x82, 2, 64);
    if (error)
        return error;
    contract->endpoints[0].address = 1;
    contract->endpoints[0].attributes = 2;
    contract->endpoints[0].max_packet = 64;
    contract->endpoints[1].address = 0x82;
    contract->endpoints[1].attributes = 2;
    contract->endpoints[1].max_packet = 64;
    return 0;
}

int melodi_usb_validate_device_at(
    const char *sysfs_root, const char *device_name,
    char serial[MELODI_RADIO_SERIAL_MAX + 1])
{
    char control_name[MELODI_USB_DEVICE_NAME_MAX + 8];
    char data_name[MELODI_USB_DEVICE_NAME_MAX + 8];
    char product[MELODI_SYSFS_VALUE_MAX];
    struct melodi_usb_contract contract = { 0 };
    unsigned int speed;
    int error;

    if (!serial || !melodi_usb_device_name_valid(device_name))
        return -EINVAL;
    error = melodi_usb_expected_number(sysfs_root, device_name, "idVendor",
                                       16, MELODI_USB_PICO_VENDOR);
    if (!error)
        error = melodi_usb_expected_number(sysfs_root, device_name,
                                           "idProduct", 16,
                                           MELODI_USB_PICO_PRODUCT);
    if (!error)
        error = melodi_usb_expected_number(sysfs_root, device_name,
                                           "bcdDevice", 16,
                                           MELODI_USB_PICO_BCD);
    if (!error)
        error = melodi_usb_expected_number(sysfs_root, device_name,
                                           "bNumConfigurations", 10, 1);
    if (!error)
        error = melodi_usb_expected_number(sysfs_root, device_name,
                                           "bConfigurationValue", 10, 1);
    if (!error)
        error = melodi_usb_expected_number(sysfs_root, device_name,
                                           "bNumInterfaces", 10, 2);
    if (!error)
        error = melodi_usb_number(sysfs_root, device_name, "speed", 10,
                                  &speed);
    if (!error)
        error = melodi_usb_read_attr(sysfs_root, device_name, "product",
                                     product, sizeof(product));
    if (!error)
        error = melodi_usb_read_attr(sysfs_root, device_name, "serial",
                                     serial, MELODI_RADIO_SERIAL_MAX + 1);
    if (error)
        return error;
    error = melodi_usb_interface_name(control_name, device_name, 0);
    if (!error)
        error = melodi_usb_interface_name(data_name, device_name, 1);
    if (!error)
        error = melodi_usb_validate_control(sysfs_root, control_name);
    if (!error)
        error = melodi_usb_validate_data(sysfs_root, data_name, &contract);
    if (error)
        return error;
    contract.vendor = MELODI_USB_PICO_VENDOR;
    contract.product_id = MELODI_USB_PICO_PRODUCT;
    contract.device_version = MELODI_USB_PICO_BCD;
    contract.interface_number = MELODI_USB_PICO_INTERFACE;
    contract.interface_class = MELODI_USB_PICO_CLASS;
    contract.interface_subclass = MELODI_USB_PICO_SUBCLASS;
    contract.interface_protocol = MELODI_USB_PICO_PROTOCOL;
    contract.endpoint_count = MELODI_USB_CONTRACT_ENDPOINTS;
    contract.profile = MELODI_USB_CONTRACT_PICO;
    contract.full_speed = speed == 12;
    contract.product = product;
    contract.product_length = strlen(product);
    contract.serial = serial;
    contract.serial_length = strlen(serial);
    return melodi_usb_contract_validate(&contract);
}

static int melodi_usb_find_serial(
    const char *sysfs_root, const char *expected_serial,
    char selected[MELODI_USB_DEVICE_NAME_MAX + 1])
{
    char devices_path[MELODI_SYSFS_PATH_MAX];
    char serial[MELODI_RADIO_SERIAL_MAX + 1];
    struct dirent *entry;
    DIR *directory;
    int error = -ENOENT;

    if (!sysfs_root || sysfs_root[0] != '/' ||
        !melodi_usb_serial_valid(expected_serial))
        return -EINVAL;
    selected[0] = '\0';
    if (snprintf(devices_path, sizeof(devices_path), "%s/bus/usb/devices",
                 sysfs_root) >= (int)sizeof(devices_path))
        return -ENAMETOOLONG;
    directory = opendir(devices_path);
    if (!directory)
        return -errno;
    while ((entry = readdir(directory))) {
        if (!melodi_usb_device_name_valid(entry->d_name))
            continue;
        error = melodi_usb_validate_device_at(sysfs_root, entry->d_name,
                                              serial);
        if (error || strcmp(serial, expected_serial)) {
            error = -ENOENT;
            continue;
        }
        if (selected[0]) {
            error = -EEXIST;
            goto out;
        }
        strcpy(selected, entry->d_name);
    }
    error = selected[0] ? 0 : -ENOENT;
out:
    if (closedir(directory) < 0 && !error)
        error = -errno;
    return error;
}

static bool melodi_tty_name_valid(const char *name)
{
    size_t length;
    size_t index;

    if (!name)
        return false;
    length = strnlen(name, MELODI_TTY_NAME_MAX + 1);
    if (!length || length > MELODI_TTY_NAME_MAX)
        return false;
    for (index = 0; index < length; index++)
        if (!isalnum((unsigned char)name[index]) && name[index] != '_' &&
            name[index] != '-')
            return false;
    return true;
}

static bool melodi_path_contains(const char *parent, const char *child)
{
    size_t length = strlen(parent);

    return !strncmp(parent, child, length) &&
           (child[length] == '\0' || child[length] == '/');
}

static int melodi_tty_find(const char *sysfs_root, const char *device_name,
                           char tty_name[MELODI_TTY_NAME_MAX + 1],
                           char device_number[MELODI_SYSFS_VALUE_MAX])
{
    char device_path[MELODI_SYSFS_PATH_MAX];
    char class_path[MELODI_SYSFS_PATH_MAX];
    char candidate_path[MELODI_SYSFS_PATH_MAX];
    char device_real[PATH_MAX];
    char candidate_real[PATH_MAX];
    struct dirent *entry;
    DIR *directory;
    bool found = false;
    int length;
    int error = -ENOENT;

    error = melodi_usb_attr_path(device_path, sysfs_root, device_name, "");
    if (error)
        return error;
    device_path[strlen(device_path) - 1] = '\0';
    if (!realpath(device_path, device_real))
        return -errno;
    length = snprintf(class_path, sizeof(class_path), "%s/class/tty",
                      sysfs_root);
    if (length < 0 || length >= (int)sizeof(class_path))
        return -ENAMETOOLONG;
    directory = opendir(class_path);
    if (!directory)
        return -errno;
    while ((entry = readdir(directory))) {
        if (!melodi_tty_name_valid(entry->d_name))
            continue;
        length = snprintf(candidate_path, sizeof(candidate_path),
                          "%s/%s/device", class_path, entry->d_name);
        if (length < 0 || length >= (int)sizeof(candidate_path)) {
            error = -ENAMETOOLONG;
            goto out;
        }
        if (!realpath(candidate_path, candidate_real) ||
            !melodi_path_contains(device_real, candidate_real))
            continue;
        if (found) {
            error = -EEXIST;
            goto out;
        }
        length = snprintf(candidate_path, sizeof(candidate_path),
                          "%s/%s/dev", class_path, entry->d_name);
        if (length < 0 || length >= (int)sizeof(candidate_path)) {
            error = -ENAMETOOLONG;
            goto out;
        }
        error = melodi_usb_read(candidate_path, device_number,
                                MELODI_SYSFS_VALUE_MAX);
        if (error)
            goto out;
        strcpy(tty_name, entry->d_name);
        found = true;
    }
    error = found ? 0 : -ENOENT;
out:
    if (closedir(directory) < 0 && !error)
        error = -errno;
    return error;
}

static int melodi_tty_parameter(const char *sysfs_root,
                                const char *parameter, const char *value)
{
    char path[MELODI_SYSFS_PATH_MAX];
    size_t value_length = strlen(value);
    ssize_t written;
    int length;
    int descriptor;

    length = snprintf(path, sizeof(path),
                      "%s/module/melodi_usb/parameters/%s",
                      sysfs_root, parameter);
    if (length < 0 || length >= (int)sizeof(path))
        return -ENAMETOOLONG;
    descriptor = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        return -errno;
    written = write(descriptor, value, value_length);
    if (close(descriptor) < 0 && written >= 0)
        return -errno;
    return written < 0 ? -errno :
           (size_t)written == value_length ? 0 : -EIO;
}

static int melodi_tty_alias(const char *device_root,
                            unsigned int interface_index,
                            const char *tty_name)
{
    char path[MELODI_SYSFS_PATH_MAX];
    char temporary[MELODI_SYSFS_PATH_MAX];
    struct stat status;
    int length;

    if (!device_root || device_root[0] != '/')
        return -EINVAL;
    length = snprintf(path, sizeof(path), "%s/ttyMEL%u", device_root,
                      interface_index);
    if (length < 0 || length >= (int)sizeof(path))
        return -ENAMETOOLONG;
    if (!lstat(path, &status)) {
        if (!S_ISLNK(status.st_mode))
            return -EEXIST;
    } else if (errno != ENOENT) {
        return -errno;
    }
    length = snprintf(temporary, sizeof(temporary), "%s/.ttyMEL%u.%ld",
                      device_root, interface_index, (long)getpid());
    if (length < 0 || length >= (int)sizeof(temporary))
        return -ENAMETOOLONG;
    if (symlink(tty_name, temporary) < 0)
        return -errno;
    if (rename(temporary, path) < 0) {
        int error = -errno;

        unlink(temporary);
        return error;
    }
    return 0;
}

int melodi_tty_attach_serial_at(const char *sysfs_root,
                                const char *device_root,
                                unsigned int interface_index,
                                const char *expected_serial)
{
    char device_name[MELODI_USB_DEVICE_NAME_MAX + 1];
    char tty_name[MELODI_TTY_NAME_MAX + 2];
    char device_number[MELODI_SYSFS_VALUE_MAX] = { 0 };
    bool alias_created = false;
    int error;

    if (interface_index >= MELODI_TTY_LIMIT)
        return -ERANGE;
    error = melodi_usb_find_serial(sysfs_root, expected_serial, device_name);
    if (!error)
        error = melodi_tty_find(sysfs_root, device_name, tty_name,
                                device_number);
    if (!error)
        error = melodi_tty_alias(device_root, interface_index, tty_name);
    if (!error)
        alias_created = true;
    if (!error)
        error = melodi_tty_parameter(sysfs_root, "attach", device_number);
    if (error && alias_created) {
        char path[MELODI_SYSFS_PATH_MAX];

        if (snprintf(path, sizeof(path), "%s/ttyMEL%u", device_root,
                     interface_index) < (int)sizeof(path))
            unlink(path);
    }
    return error;
}

int melodi_tty_release_at(const char *sysfs_root, const char *device_root,
                          unsigned int interface_index)
{
    char device_number[MELODI_SYSFS_VALUE_MAX];
    char tty_name[MELODI_TTY_NAME_MAX + 2];
    char path[MELODI_SYSFS_PATH_MAX];
    ssize_t tty_length;
    int length;
    int error;

    if (!sysfs_root || sysfs_root[0] != '/' || !device_root ||
        device_root[0] != '/' || interface_index >= MELODI_TTY_LIMIT)
        return -EINVAL;
    length = snprintf(path, sizeof(path), "%s/ttyMEL%u", device_root,
                      interface_index);
    if (length < 0 || length >= (int)sizeof(path))
        return -ENAMETOOLONG;
    tty_length = readlink(path, tty_name, sizeof(tty_name) - 1);
    if (tty_length < 0)
        return -errno;
    tty_name[tty_length] = '\0';
    if (!melodi_tty_name_valid(tty_name))
        return -EINVAL;
    length = snprintf(path, sizeof(path), "%s/class/tty/%s/dev",
                      sysfs_root, tty_name);
    if (length < 0 || length >= (int)sizeof(path))
        return -ENAMETOOLONG;
    error = melodi_usb_read(path, device_number, sizeof(device_number));
    if (error == -ENOENT) {
        length = snprintf(path, sizeof(path), "%s/ttyMEL%u", device_root,
                          interface_index);
        return unlink(path) < 0 ? -errno : 0;
    }
    if (!error)
        error = melodi_tty_parameter(sysfs_root, "release", device_number);
    if (error)
        return error;
    length = snprintf(path, sizeof(path), "%s/ttyMEL%u", device_root,
                      interface_index);
    return unlink(path) < 0 ? -errno : 0;
}
