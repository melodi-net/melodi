/* SPDX-License-Identifier: GPL-2.0-only */
#include "contract.h"

#include <assert.h>
#include <errno.h>
#include <string.h>

static struct melodi_usb_contract valid_contract(void)
{
    static const char product[] = MELODI_USB_TEST_PRODUCT_NAME;
    static const char serial[] = "melodi-emulator-1";
    struct melodi_usb_contract contract = {
        .endpoints = {
            { MELODI_USB_TEST_MAX_PACKET, MELODI_USB_TEST_OUT,
              MELODI_USB_ENDPOINT_BULK },
            { MELODI_USB_TEST_MAX_PACKET, MELODI_USB_TEST_IN,
              MELODI_USB_ENDPOINT_BULK },
        },
        .product = product,
        .serial = serial,
        .product_length = sizeof(product) - 1,
        .serial_length = sizeof(serial) - 1,
        .vendor = MELODI_USB_TEST_VENDOR,
        .product_id = MELODI_USB_TEST_PRODUCT,
        .device_version = MELODI_USB_TEST_BCD,
        .interface_number = MELODI_USB_TEST_INTERFACE,
        .interface_class = MELODI_USB_TEST_CLASS,
        .interface_subclass = MELODI_USB_TEST_SUBCLASS,
        .interface_protocol = MELODI_USB_TEST_PROTOCOL,
        .endpoint_count = MELODI_USB_CONTRACT_ENDPOINTS,
        .profile = MELODI_USB_CONTRACT_TEST,
        .high_speed = true,
    };

    return contract;
}

static struct melodi_usb_contract valid_pico_contract(void)
{
    static const char product[] = MELODI_USB_PICO_PRODUCT_NAME;
    static const char serial[] = "DF643CF0134A4C26";
    struct melodi_usb_contract contract = {
        .endpoints = {
            { MELODI_USB_CDC_MAX_PACKET, MELODI_USB_CDC_OUT,
              MELODI_USB_ENDPOINT_BULK },
            { MELODI_USB_CDC_MAX_PACKET, MELODI_USB_CDC_IN,
              MELODI_USB_ENDPOINT_BULK },
        },
        .product = product,
        .serial = serial,
        .product_length = sizeof(product) - 1,
        .serial_length = sizeof(serial) - 1,
        .vendor = MELODI_USB_PICO_VENDOR,
        .product_id = MELODI_USB_PICO_PRODUCT,
        .device_version = MELODI_USB_PICO_BCD,
        .interface_number = MELODI_USB_CDC_INTERFACE,
        .interface_class = MELODI_USB_CDC_CLASS,
        .interface_subclass = MELODI_USB_CDC_SUBCLASS,
        .interface_protocol = MELODI_USB_CDC_PROTOCOL,
        .endpoint_count = MELODI_USB_CONTRACT_ENDPOINTS,
        .profile = MELODI_USB_CONTRACT_CDC,
        .full_speed = true,
    };

    return contract;
}

int main(void)
{
    struct melodi_usb_contract contract = valid_contract();

    assert(melodi_usb_contract_validate(&contract) == 0);
    contract.endpoints[0].address = MELODI_USB_TEST_IN;
    contract.endpoints[1].address = MELODI_USB_TEST_OUT;
    assert(melodi_usb_contract_validate(&contract) == 0);
    contract = valid_contract();
    contract.interface_number++;
    assert(melodi_usb_contract_validate(&contract) == -ENODEV);
    assert(melodi_usb_firmware_supported("melodi-usb-test-1", 17, true));
    assert(!melodi_usb_firmware_supported("2.8.0", 5, true));
    assert(melodi_usb_firmware_supported("2.7.20", 6, false));
    assert(melodi_usb_firmware_supported("2.8.0.db3eb91", 13, false));
    assert(!melodi_usb_firmware_supported("2.6.11", 6, false));
    assert(!melodi_usb_firmware_supported("2.9.0", 5, false));
    assert(!melodi_usb_firmware_supported("2.8.x", 5, false));
    contract = valid_contract();
    contract.alternate = 1;
    assert(melodi_usb_contract_validate(&contract) == -ENODEV);
    contract = valid_contract();
    contract.interface_class--;
    assert(melodi_usb_contract_validate(&contract) == -ENODEV);
    contract = valid_contract();
    contract.interface_subclass++;
    assert(melodi_usb_contract_validate(&contract) == -ENODEV);
    contract = valid_contract();
    contract.interface_protocol++;
    assert(melodi_usb_contract_validate(&contract) == -ENODEV);
    contract = valid_contract();
    contract.high_speed = false;
    assert(melodi_usb_contract_validate(&contract) == -ENODEV);
    contract = valid_contract();
    contract.endpoint_count = 1;
    assert(melodi_usb_contract_validate(&contract) == -ENODEV);
    contract = valid_contract();
    contract.endpoints[0].max_packet = 64;
    assert(melodi_usb_contract_validate(&contract) == -ENODEV);
    contract = valid_contract();
    contract.endpoints[1].attributes = 3;
    assert(melodi_usb_contract_validate(&contract) == -ENODEV);
    contract = valid_contract();
    contract.endpoints[1].address = 0x82;
    assert(melodi_usb_contract_validate(&contract) == -ENODEV);
    contract = valid_contract();
    contract.product = "Melodi USB Test Radi0";
    assert(melodi_usb_contract_validate(&contract) == -ENODEV);
    contract = valid_contract();
    contract.product = NULL;
    assert(melodi_usb_contract_validate(&contract) == -ENODEV);
    contract = valid_contract();
    contract.serial = NULL;
    assert(melodi_usb_contract_validate(&contract) == -ENODEV);
    contract = valid_contract();
    contract.serial = "bad,serial";
    contract.serial_length = strlen(contract.serial);
    assert(melodi_usb_contract_validate(&contract) == -ENODEV);
    contract = valid_pico_contract();
    assert(melodi_usb_contract_validate(&contract) == 0);
    contract.endpoints[0].address = MELODI_USB_CDC_IN;
    contract.endpoints[1].address = MELODI_USB_CDC_OUT;
    assert(melodi_usb_contract_validate(&contract) == 0);
    contract = valid_pico_contract();
    contract.serial = "df643cf0134a4c26";
    assert(melodi_usb_contract_validate(&contract) == -ENODEV);
    contract = valid_pico_contract();
    contract.high_speed = true;
    contract.full_speed = false;
    assert(melodi_usb_contract_validate(&contract) == -ENODEV);
    contract = valid_pico_contract();
    contract.product_id++;
    assert(melodi_usb_contract_validate(&contract) == -ENODEV);
    assert(melodi_usb_contract_validate(NULL) == -ENODEV);
    return 0;
}
