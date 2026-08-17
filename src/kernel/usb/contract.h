/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MELODI_USB_CONTRACT_H
#define MELODI_USB_CONTRACT_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef u8 melodi_usb_u8;
typedef u16 melodi_usb_u16;
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef uint8_t melodi_usb_u8;
typedef uint16_t melodi_usb_u16;
#endif

#define MELODI_USB_TEST_VENDOR 0x1d6b
#define MELODI_USB_TEST_PRODUCT 0xf00d
#define MELODI_USB_TEST_BCD 0x0100
#define MELODI_USB_TEST_INTERFACE 0
#define MELODI_USB_TEST_CLASS 0xff
#define MELODI_USB_TEST_SUBCLASS 0x4d
#define MELODI_USB_TEST_PROTOCOL 0x01
#define MELODI_USB_TEST_IN 0x81
#define MELODI_USB_TEST_OUT 0x01
#define MELODI_USB_TEST_MAX_PACKET 512
#define MELODI_USB_TEST_PRODUCT_NAME "Melodi USB Test Radio"
#define MELODI_USB_PICO_VENDOR 0x2e8a
#define MELODI_USB_PICO_PRODUCT 0x000a
#define MELODI_USB_PICO_BCD 0x0100
#define MELODI_USB_CDC_CONTROL_INTERFACE 0
#define MELODI_USB_CDC_CONTROL_CLASS 0x02
#define MELODI_USB_CDC_CONTROL_SUBCLASS 0x02
#define MELODI_USB_CDC_CONTROL_PROTOCOL 0x00
#define MELODI_USB_CDC_CONTROL_IN 0x81
#define MELODI_USB_CDC_CONTROL_MAX_PACKET 8
#define MELODI_USB_CDC_INTERFACE 1
#define MELODI_USB_CDC_CLASS 0x0a
#define MELODI_USB_CDC_SUBCLASS 0x00
#define MELODI_USB_CDC_PROTOCOL 0x00
#define MELODI_USB_CDC_IN 0x82
#define MELODI_USB_CDC_OUT 0x01
#define MELODI_USB_CDC_MAX_PACKET 64
#define MELODI_USB_PICO_PRODUCT_NAME "Pico"
#define MELODI_USB_FEATHER_VENDOR 0x239a
#define MELODI_USB_FEATHER_PRODUCT 0x812d
#define MELODI_USB_FEATHER_BCD 0x0100
#define MELODI_USB_FEATHER_PRODUCT_NAME "Feather RP2040 RFM"
#define MELODI_USB_CONTRACT_ENDPOINTS 2
#define MELODI_USB_ENDPOINT_BULK 2

enum melodi_usb_contract_profile {
    MELODI_USB_CONTRACT_TEST = 1,
    MELODI_USB_CONTRACT_CDC,
};

struct melodi_usb_contract_endpoint {
    melodi_usb_u16 max_packet;
    melodi_usb_u8 address;
    melodi_usb_u8 attributes;
};

struct melodi_usb_contract {
    struct melodi_usb_contract_endpoint endpoints[2];
    const char *product;
    const char *serial;
    size_t product_length;
    size_t serial_length;
    melodi_usb_u16 vendor;
    melodi_usb_u16 product_id;
    melodi_usb_u16 device_version;
    melodi_usb_u8 interface_number;
    melodi_usb_u8 alternate;
    melodi_usb_u8 interface_class;
    melodi_usb_u8 interface_subclass;
    melodi_usb_u8 interface_protocol;
    melodi_usb_u8 endpoint_count;
    melodi_usb_u8 profile;
    bool full_speed;
    bool high_speed;
};

int melodi_usb_contract_validate(const struct melodi_usb_contract *contract);
bool melodi_usb_firmware_supported(const char *firmware, size_t length,
                                   bool test_profile);

#endif
