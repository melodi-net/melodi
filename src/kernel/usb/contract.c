/* SPDX-License-Identifier: GPL-2.0-only */
#include "contract.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

int melodi_usb_contract_validate(const struct melodi_usb_contract *contract)
{
    static const char test_product[] = MELODI_USB_TEST_PRODUCT_NAME;
    static const char pico_product[] = MELODI_USB_PICO_PRODUCT_NAME;
    const char *product;
    size_t product_length;
    unsigned int max_packet;
    unsigned int in;
    unsigned int out;
    bool found_in = false;
    bool found_out = false;
    size_t index;

    if (!contract || contract->alternate ||
        contract->endpoint_count != MELODI_USB_CONTRACT_ENDPOINTS ||
        !contract->product || !contract->serial ||
        !contract->serial_length || contract->serial_length > 64)
        return -ENODEV;
    if (contract->profile == MELODI_USB_CONTRACT_TEST) {
        if (contract->vendor != MELODI_USB_TEST_VENDOR ||
            contract->product_id != MELODI_USB_TEST_PRODUCT ||
            contract->device_version != MELODI_USB_TEST_BCD ||
            contract->interface_number != MELODI_USB_TEST_INTERFACE ||
            contract->interface_class != MELODI_USB_TEST_CLASS ||
            contract->interface_subclass != MELODI_USB_TEST_SUBCLASS ||
            contract->interface_protocol != MELODI_USB_TEST_PROTOCOL ||
            !contract->high_speed)
            return -ENODEV;
        product = test_product;
        product_length = sizeof(test_product) - 1;
        max_packet = MELODI_USB_TEST_MAX_PACKET;
        in = MELODI_USB_TEST_IN;
        out = MELODI_USB_TEST_OUT;
    } else if (contract->profile == MELODI_USB_CONTRACT_PICO) {
        if (contract->vendor != MELODI_USB_PICO_VENDOR ||
            contract->product_id != MELODI_USB_PICO_PRODUCT ||
            contract->device_version != MELODI_USB_PICO_BCD ||
            contract->interface_number != MELODI_USB_PICO_INTERFACE ||
            contract->interface_class != MELODI_USB_PICO_CLASS ||
            contract->interface_subclass != MELODI_USB_PICO_SUBCLASS ||
            contract->interface_protocol != MELODI_USB_PICO_PROTOCOL ||
            !contract->full_speed || contract->serial_length != 16)
            return -ENODEV;
        product = pico_product;
        product_length = sizeof(pico_product) - 1;
        max_packet = MELODI_USB_PICO_MAX_PACKET;
        in = MELODI_USB_PICO_IN;
        out = MELODI_USB_PICO_OUT;
    } else {
        return -ENODEV;
    }
    if (contract->product_length != product_length ||
        memcmp(contract->product, product, product_length))
        return -ENODEV;
    for (index = 0; index < contract->serial_length; index++)
        if (contract->serial[index] < 0x21 ||
            contract->serial[index] > 0x7e ||
            contract->serial[index] == ',')
            return -ENODEV;
    if (contract->profile == MELODI_USB_CONTRACT_PICO)
        for (index = 0; index < contract->serial_length; index++)
            if (!((contract->serial[index] >= '0' &&
                   contract->serial[index] <= '9') ||
                  (contract->serial[index] >= 'A' &&
                   contract->serial[index] <= 'F')))
                return -ENODEV;
    for (index = 0; index < MELODI_USB_CONTRACT_ENDPOINTS; index++) {
        const struct melodi_usb_contract_endpoint *endpoint =
            &contract->endpoints[index];

        if (endpoint->attributes != MELODI_USB_ENDPOINT_BULK ||
            endpoint->max_packet != max_packet)
            return -ENODEV;
        if (endpoint->address == in && !found_in)
            found_in = true;
        else if (endpoint->address == out && !found_out)
            found_out = true;
        else
            return -ENODEV;
    }
    return found_in && found_out ? 0 : -ENODEV;
}

bool melodi_usb_firmware_supported(const char *firmware, size_t length,
                                   bool test_profile)
{
    static const char test_firmware[] = "melodi-usb-test-1";
    unsigned int minor;
    size_t index;

    if (!firmware || !length)
        return false;
    if (test_profile)
        return length == sizeof(test_firmware) - 1 &&
               !memcmp(firmware, test_firmware, sizeof(test_firmware) - 1);
    if (length < 5 || firmware[0] != '2' || firmware[1] != '.' ||
        firmware[3] != '.' || firmware[2] < '0' || firmware[2] > '9')
        return false;
    minor = firmware[2] - '0';
    if (minor < 7 || minor > 8)
        return false;
    for (index = 4; index < length; index++)
        if (firmware[index] < 0x20 || firmware[index] > 0x7e)
            return false;
    return firmware[4] >= '0' && firmware[4] <= '9';
}
