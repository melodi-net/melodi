/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/usb/composite.h>
#include <linux/workqueue.h>

#include "contract.h"
#include "radio.h"

#define MELODI_EMULATOR_RX_LIMIT 32
#define MELODI_EMULATOR_TX_LIMIT 32
#define MELODI_EMULATOR_BUFFER 512

struct melodi_emulator_chunk {
    struct list_head node;
    u16 length;
    u8 data[MELODI_EMULATOR_BUFFER];
};

struct melodi_emulator {
    struct usb_function function;
    struct usb_composite_driver driver;
    struct usb_device_descriptor device;
    struct usb_interface_descriptor interface;
    struct usb_endpoint_descriptor fs_out;
    struct usb_endpoint_descriptor fs_in;
    struct usb_endpoint_descriptor hs_out;
    struct usb_endpoint_descriptor hs_in;
    struct usb_descriptor_header *fs_descriptors[4];
    struct usb_descriptor_header *hs_descriptors[4];
    struct usb_string strings[5];
    struct usb_gadget_strings string_table;
    struct usb_gadget_strings *device_strings[2];
    struct usb_configuration configuration;
    struct usb_composite_dev *composite;
    struct melodi_emulator *peer;
    struct usb_ep *in_endpoint;
    struct usb_ep *out_endpoint;
    struct usb_request *out_request;
    struct workqueue_struct *workqueue;
    struct work_struct work;
    spinlock_t lock;
    struct list_head queue;
    unsigned int queued;
    atomic_t transmit_count;
    atomic_t packet_id;
    struct melodi_radio_stream stream;
    u32 locator;
    bool enabled;
};

static struct melodi_emulator melodi_emulators[2];
static bool near_miss;
static bool firmware_refusal;
static bool unsafe_configuration;
static bool pause_handshake;
static bool malformed_protobuf;
static unsigned int dribble;
module_param(near_miss, bool, 0444);
module_param(firmware_refusal, bool, 0444);
module_param(unsafe_configuration, bool, 0444);
module_param(pause_handshake, bool, 0444);
module_param(malformed_protobuf, bool, 0444);
module_param(dribble, uint, 0444);

static const char *const melodi_emulator_driver_names[] = {
    "melodi_usb_emulator_1",
    "melodi_usb_emulator_2",
};

static const char *const melodi_emulator_serials[] = {
    "melodi-emulator-1",
    "melodi-emulator-2",
};

static const struct usb_device_descriptor melodi_emulator_device = {
    .bLength = sizeof(struct usb_device_descriptor),
    .bDescriptorType = USB_DT_DEVICE,
    .bcdUSB = cpu_to_le16(0x0200),
    .bDeviceClass = USB_CLASS_PER_INTERFACE,
    .bMaxPacketSize0 = 64,
    .idVendor = cpu_to_le16(MELODI_USB_TEST_VENDOR),
    .idProduct = cpu_to_le16(MELODI_USB_TEST_PRODUCT),
    .bcdDevice = cpu_to_le16(MELODI_USB_TEST_BCD),
    .bNumConfigurations = 1,
};

static const struct usb_interface_descriptor melodi_emulator_interface = {
    .bLength = USB_DT_INTERFACE_SIZE,
    .bDescriptorType = USB_DT_INTERFACE,
    .bNumEndpoints = 2,
    .bInterfaceClass = MELODI_USB_TEST_CLASS,
    .bInterfaceSubClass = MELODI_USB_TEST_SUBCLASS,
    .bInterfaceProtocol = MELODI_USB_TEST_PROTOCOL,
};

static const struct usb_endpoint_descriptor melodi_emulator_fs_out = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = MELODI_USB_TEST_OUT,
    .bmAttributes = MELODI_USB_ENDPOINT_BULK,
    .wMaxPacketSize = cpu_to_le16(64),
};

static const struct usb_endpoint_descriptor melodi_emulator_fs_in = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = MELODI_USB_TEST_IN,
    .bmAttributes = MELODI_USB_ENDPOINT_BULK,
    .wMaxPacketSize = cpu_to_le16(64),
};

static const struct usb_endpoint_descriptor melodi_emulator_hs_out = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = MELODI_USB_TEST_OUT,
    .bmAttributes = MELODI_USB_ENDPOINT_BULK,
    .wMaxPacketSize = cpu_to_le16(MELODI_USB_TEST_MAX_PACKET),
};

static const struct usb_endpoint_descriptor melodi_emulator_hs_in = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = MELODI_USB_TEST_IN,
    .bmAttributes = MELODI_USB_ENDPOINT_BULK,
    .wMaxPacketSize = cpu_to_le16(MELODI_USB_TEST_MAX_PACKET),
};

static const struct usb_configuration melodi_emulator_configuration = {
    .label = "Melodi test radio",
    .bConfigurationValue = 1,
    .bmAttributes = USB_CONFIG_ATT_ONE,
    .MaxPower = 2,
};


static void melodi_emulator_transmit_complete(struct usb_ep *endpoint,
                                              struct usb_request *request)
{
    struct melodi_emulator *emulator = request->context;

    kfree(request->buf);
    usb_ep_free_request(endpoint, request);
    atomic_dec(&emulator->transmit_count);
}
static int melodi_emulator_queue_bytes(struct melodi_emulator *emulator,
                                       const u8 *data, size_t length)
{
    struct usb_request *request;
    size_t chunk = dribble ? dribble : length;
    size_t offset = 0;
    int error;

    if (!READ_ONCE(emulator->enabled) || !data || !length)
        return -ENETDOWN;
    if (length > MELODI_EMULATOR_BUFFER)
        return -EMSGSIZE;
    while (offset < length) {
        size_t part = min(chunk, length - offset);

        if (atomic_inc_return(&emulator->transmit_count) >
            MELODI_EMULATOR_TX_LIMIT) {
            atomic_dec(&emulator->transmit_count);
            return -ENOSPC;
        }
        request = usb_ep_alloc_request(emulator->in_endpoint, GFP_KERNEL);
        if (!request) {
            error = -ENOMEM;
            goto decrement;
        }
        request->buf = kmemdup(data + offset, part, GFP_KERNEL);
        if (!request->buf) {
            error = -ENOMEM;
            goto free_request;
        }
        request->length = part;
        request->complete = melodi_emulator_transmit_complete;
        request->context = emulator;
        error = usb_ep_queue(emulator->in_endpoint, request, GFP_KERNEL);
        if (error) {
            kfree(request->buf);
            goto free_request;
        }
        offset += part;
    }
    return 0;
free_request:
    usb_ep_free_request(emulator->in_endpoint, request);
decrement:
    atomic_dec(&emulator->transmit_count);
    return error;
}

static int melodi_emulator_send_info(struct melodi_emulator *emulator)
{
    struct melodi_radio_info info = {};
    u8 message[MELODI_EMULATOR_BUFFER];
    size_t length;
    int error;

    info.abi_version = MELODI_RADIO_VERSION;
    info.packet_mtu = MELODI_RADIO_PACKET_MAX;
    info.queue_depth = 8;
    strscpy(info.firmware, firmware_refusal ? "unsupported" : "melodi-emu-1",
            sizeof(info.firmware));
    strscpy(info.hardware, "melodi-usb-emulator", sizeof(info.hardware));
    error = melodi_radio_encode_info(&info, message, sizeof(message),
                                     &length);
    if (error)
        return error;
    if (malformed_protobuf)
        message[MELODI_RADIO_HEADER_SIZE] ^= 0xff;
    return melodi_emulator_queue_bytes(emulator, message, length);
}

static int melodi_emulator_send_status(struct melodi_emulator *emulator)
{
    struct melodi_radio_status status = {};
    u8 message[MELODI_EMULATOR_BUFFER];
    size_t length;
    int error;

    status.locator = READ_ONCE(emulator->locator);
    status.queue_depth = 8;
    status.queue_free = 8;
    if (unsafe_configuration) {
        status.state = MELODI_RADIO_STATE_FAILED;
        status.fault = MELODI_RADIO_FAULT_MODEM;
    } else if (status.locator) {
        status.state = MELODI_RADIO_STATE_READY;
    } else {
        status.state = MELODI_RADIO_STATE_IDLE;
    }
    error = melodi_radio_encode_status(&status, message, sizeof(message),
                                       &length);
    if (error)
        return error;
    return melodi_emulator_queue_bytes(emulator, message, length);
}

static int melodi_emulator_send_result(struct melodi_emulator *emulator,
                                       u32 cookie, u8 result)
{
    struct melodi_radio_result_report report = {};
    u8 message[MELODI_EMULATOR_BUFFER];
    size_t length;
    int error;

    report.cookie = cookie;
    report.duration_us = 1000;
    report.result = result;
    error = melodi_radio_encode_result(&report, message, sizeof(message),
                                       &length);
    if (error)
        return error;
    return melodi_emulator_queue_bytes(emulator, message, length);
}

static int melodi_emulator_forward(struct melodi_emulator *emulator,
                                   const struct melodi_radio_transmit *request)
{
    struct melodi_emulator *peer = emulator->peer;
    struct melodi_radio_receive receive = {};
    u8 message[MELODI_EMULATOR_BUFFER];
    size_t length;
    u32 source = READ_ONCE(emulator->locator);
    u32 destination = READ_ONCE(peer->locator);
    int error;

    if (!source || !destination)
        return -EHOSTUNREACH;
    if (request->destination != destination &&
        request->destination != MELODI_RADIO_LOCATOR_BROADCAST)
        return 0;
    receive.source = source;
    receive.destination = request->destination;
    receive.rssi = -90;
    receive.snr = 8;
    receive.payload = request->payload;
    receive.payload_length = request->payload_length;
    error = melodi_radio_encode_receive(&receive, message, sizeof(message),
                                        &length);
    if (error)
        return error;
    return melodi_emulator_queue_bytes(peer, message, length);
}

static int melodi_emulator_handle_message(
    struct melodi_emulator *emulator,
    const struct melodi_radio_header *header, const u8 *payload)
{
    struct melodi_radio_configure config;
    struct melodi_radio_transmit request;
    int error;

    switch (header->type) {
    case MELODI_RADIO_T_IDENTIFY:
        return melodi_emulator_send_info(emulator);
    case MELODI_RADIO_T_CONFIGURE:
        error = melodi_radio_decode_configure(payload, header->length,
                                              &config);
        if (error)
            return error;
        WRITE_ONCE(emulator->locator, config.locator);
        if (pause_handshake)
            return 0;
        return melodi_emulator_send_status(emulator);
    case MELODI_RADIO_T_TRANSMIT:
        error = melodi_radio_decode_transmit(payload, header->length,
                                             &request);
        if (error)
            return error;
        if (!READ_ONCE(emulator->locator))
            return melodi_emulator_send_result(
                emulator, request.cookie, MELODI_RADIO_RESULT_NOT_READY);
        error = melodi_emulator_forward(emulator, &request);
        if (error)
            return error;
        return melodi_emulator_send_result(emulator, request.cookie,
                                           MELODI_RADIO_RESULT_SENT);
    case MELODI_RADIO_T_RESET:
        WRITE_ONCE(emulator->locator, 0);
        return melodi_emulator_send_status(emulator);
    default:
        return -EOPNOTSUPP;
    }
}

static void melodi_emulator_parse(struct melodi_emulator *emulator,
                                  const struct melodi_emulator_chunk *chunk)
{
    const struct melodi_radio_header *header;
    const u8 *payload;
    unsigned int index;
    int result;

    for (index = 0; index < chunk->length; index++) {
        result = melodi_radio_stream_feed(&emulator->stream,
                                          chunk->data[index], &header,
                                          &payload);
        if (result < 0) {
            pr_err_ratelimited("melodi emulator stream: %d\n", result);
            continue;
        }
        if (!result)
            continue;
        result = melodi_emulator_handle_message(emulator, header, payload);
        if (result)
            pr_err_ratelimited("melodi emulator message: %d\n", result);
    }
}


static void melodi_emulator_work(struct work_struct *work)
{
    struct melodi_emulator *emulator = container_of(
        work, struct melodi_emulator, work);
    struct melodi_emulator_chunk *chunk;
    unsigned long flags;

    for (;;) {
        spin_lock_irqsave(&emulator->lock, flags);
        chunk = list_first_entry_or_null(&emulator->queue,
                                         struct melodi_emulator_chunk, node);
        if (chunk) {
            list_del(&chunk->node);
            emulator->queued--;
        }
        spin_unlock_irqrestore(&emulator->lock, flags);
        if (!chunk)
            break;
        melodi_emulator_parse(emulator, chunk);
        kfree(chunk);
    }
}

static void melodi_emulator_out_complete(struct usb_ep *endpoint,
                                         struct usb_request *request)
{
    struct melodi_emulator *emulator = request->context;
    struct melodi_emulator_chunk *chunk = NULL;
    unsigned long flags;
    int error;

    if (!request->status && request->actual) {
        chunk = kmalloc(sizeof(*chunk), GFP_ATOMIC);
        if (chunk) {
            chunk->length = request->actual;
            memcpy(chunk->data, request->buf, chunk->length);
            spin_lock_irqsave(&emulator->lock, flags);
            if (emulator->queued < MELODI_EMULATOR_RX_LIMIT) {
                list_add_tail(&chunk->node, &emulator->queue);
                emulator->queued++;
                chunk = NULL;
            }
            spin_unlock_irqrestore(&emulator->lock, flags);
            kfree(chunk);
            queue_work(emulator->workqueue, &emulator->work);
        }
    }
    if (!READ_ONCE(emulator->enabled))
        return;
    request->length = MELODI_EMULATOR_BUFFER;
    error = usb_ep_queue(endpoint, request, GFP_ATOMIC);
    if (error)
        pr_err_ratelimited("melodi emulator receive: %d\n", error);
}

static void melodi_emulator_queue_clear(struct melodi_emulator *emulator)
{
    struct melodi_emulator_chunk *chunk;
    struct melodi_emulator_chunk *next;
    LIST_HEAD(pending);
    unsigned long flags;

    spin_lock_irqsave(&emulator->lock, flags);
    list_splice_init(&emulator->queue, &pending);
    emulator->queued = 0;
    spin_unlock_irqrestore(&emulator->lock, flags);
    list_for_each_entry_safe(chunk, next, &pending, node) {
        list_del(&chunk->node);
        kfree(chunk);
    }
}

static void melodi_emulator_disable(struct usb_function *function)
{
    struct melodi_emulator *emulator = container_of(
        function, struct melodi_emulator, function);

    WRITE_ONCE(emulator->enabled, false);
    if (emulator->out_endpoint)
        usb_ep_disable(emulator->out_endpoint);
    if (emulator->in_endpoint)
        usb_ep_disable(emulator->in_endpoint);
    if (emulator->out_request) {
        kfree(emulator->out_request->buf);
        usb_ep_free_request(emulator->out_endpoint,
                            emulator->out_request);
        emulator->out_request = NULL;
    }
    flush_workqueue(emulator->workqueue);
    melodi_emulator_queue_clear(emulator);
    melodi_radio_stream_init(&emulator->stream);
}

static int melodi_emulator_set_alt(struct usb_function *function,
                                   unsigned int interface,
                                   unsigned int alternate)
{
    struct melodi_emulator *emulator = container_of(
        function, struct melodi_emulator, function);
    struct usb_gadget *gadget = emulator->composite->gadget;
    int error;

    if (interface != emulator->interface.bInterfaceNumber || alternate)
        return -EINVAL;
    if (emulator->enabled)
        melodi_emulator_disable(function);
    error = config_ep_by_speed(gadget, function, emulator->out_endpoint);
    if (!error)
        error = usb_ep_enable(emulator->out_endpoint);
    if (error)
        return error;
    error = config_ep_by_speed(gadget, function, emulator->in_endpoint);
    if (!error)
        error = usb_ep_enable(emulator->in_endpoint);
    if (error)
        goto disable_out;
    emulator->out_request = usb_ep_alloc_request(emulator->out_endpoint,
                                                  GFP_KERNEL);
    if (!emulator->out_request) {
        error = -ENOMEM;
        goto disable_in;
    }
    emulator->out_request->buf = kmalloc(MELODI_EMULATOR_BUFFER,
                                         GFP_KERNEL);
    if (!emulator->out_request->buf) {
        error = -ENOMEM;
        goto free_request;
    }
    emulator->out_request->length = MELODI_EMULATOR_BUFFER;
    emulator->out_request->complete = melodi_emulator_out_complete;
    emulator->out_request->context = emulator;
    WRITE_ONCE(emulator->enabled, true);
    error = usb_ep_queue(emulator->out_endpoint, emulator->out_request,
                         GFP_KERNEL);
    if (!error)
        return 0;
    WRITE_ONCE(emulator->enabled, false);
    kfree(emulator->out_request->buf);
free_request:
    usb_ep_free_request(emulator->out_endpoint, emulator->out_request);
    emulator->out_request = NULL;
disable_in:
    usb_ep_disable(emulator->in_endpoint);
disable_out:
    usb_ep_disable(emulator->out_endpoint);
    return error;
}

static int melodi_emulator_function_bind(struct usb_configuration *config,
                                         struct usb_function *function)
{
    struct melodi_emulator *emulator = container_of(
        function, struct melodi_emulator, function);
    struct usb_composite_dev *composite = config->cdev;
    int interface;
    int error;

    interface = usb_interface_id(config, function);
    if (interface < 0)
        return interface;
    if (interface != 0)
        return -ENODEV;
    emulator->interface.bInterfaceNumber = interface;
    emulator->in_endpoint = usb_ep_autoconfig(
        composite->gadget, &emulator->fs_in);
    emulator->out_endpoint = usb_ep_autoconfig(
        composite->gadget, &emulator->fs_out);
    if (!emulator->in_endpoint || !emulator->out_endpoint ||
        emulator->fs_in.bEndpointAddress != MELODI_USB_TEST_IN ||
        emulator->fs_out.bEndpointAddress != MELODI_USB_TEST_OUT)
        return -ENODEV;
    emulator->hs_in.bEndpointAddress = emulator->fs_in.bEndpointAddress;
    emulator->hs_out.bEndpointAddress = emulator->fs_out.bEndpointAddress;
    emulator->in_endpoint->driver_data = emulator;
    emulator->out_endpoint->driver_data = emulator;
    emulator->workqueue = alloc_ordered_workqueue(
        "melodi_usb_emulator", WQ_MEM_RECLAIM);
    if (!emulator->workqueue)
        return -ENOMEM;
    error = usb_assign_descriptors(function, emulator->fs_descriptors,
                                   emulator->hs_descriptors,
                                   NULL, NULL);
    if (error) {
        destroy_workqueue(emulator->workqueue);
        emulator->workqueue = NULL;
    }
    return error;
}

static void melodi_emulator_function_unbind(
    struct usb_configuration *config, struct usb_function *function)
{
    struct melodi_emulator *emulator = container_of(
        function, struct melodi_emulator, function);

    (void)config;
    if (emulator->enabled || emulator->out_request)
        melodi_emulator_disable(function);
    usb_free_all_descriptors(function);
    if (emulator->workqueue) {
        destroy_workqueue(emulator->workqueue);
        emulator->workqueue = NULL;
    }
    emulator->in_endpoint = NULL;
    emulator->out_endpoint = NULL;
}

static int melodi_emulator_configuration_bind(
    struct usb_configuration *configuration)
{
    struct melodi_emulator *emulator = container_of(
        configuration, struct melodi_emulator, configuration);

    return usb_add_function(configuration, &emulator->function);
}

static int melodi_emulator_bind(struct usb_composite_dev *composite)
{
    struct melodi_emulator *emulator = container_of(
        composite->driver, struct melodi_emulator, driver);
    int error;

    emulator->composite = composite;
    error = usb_string_ids_tab(composite, emulator->strings);
    if (error < 0)
        return error;
    emulator->device.iManufacturer =
        emulator->strings[USB_GADGET_MANUFACTURER_IDX].id;
    emulator->device.iProduct =
        emulator->strings[USB_GADGET_PRODUCT_IDX].id;
    emulator->device.iSerialNumber =
        emulator->strings[USB_GADGET_SERIAL_IDX].id;
    emulator->interface.iInterface =
        emulator->strings[USB_GADGET_FIRST_AVAIL_IDX].id;
    return usb_add_config(composite, &emulator->configuration,
                          melodi_emulator_configuration_bind);
}

static void melodi_emulator_initialize(struct melodi_emulator *emulator,
                                       unsigned int index)
{
    memset(emulator, 0, sizeof(*emulator));
    emulator->device = melodi_emulator_device;
    emulator->interface = melodi_emulator_interface;
    if (near_miss)
        emulator->interface.bInterfaceProtocol++;
    emulator->fs_out = melodi_emulator_fs_out;
    emulator->fs_in = melodi_emulator_fs_in;
    emulator->hs_out = melodi_emulator_hs_out;
    emulator->hs_in = melodi_emulator_hs_in;
    emulator->fs_descriptors[0] =
        (struct usb_descriptor_header *)&emulator->interface;
    emulator->fs_descriptors[1] =
        (struct usb_descriptor_header *)&emulator->fs_out;
    emulator->fs_descriptors[2] =
        (struct usb_descriptor_header *)&emulator->fs_in;
    emulator->hs_descriptors[0] =
        (struct usb_descriptor_header *)&emulator->interface;
    emulator->hs_descriptors[1] =
        (struct usb_descriptor_header *)&emulator->hs_out;
    emulator->hs_descriptors[2] =
        (struct usb_descriptor_header *)&emulator->hs_in;
    emulator->strings[USB_GADGET_MANUFACTURER_IDX].s = "Melodi";
    emulator->strings[USB_GADGET_PRODUCT_IDX].s =
        MELODI_USB_TEST_PRODUCT_NAME;
    emulator->strings[USB_GADGET_SERIAL_IDX].s =
        melodi_emulator_serials[index];
    emulator->strings[USB_GADGET_FIRST_AVAIL_IDX].s =
        "Melodi radio transport";
    emulator->string_table.language = 0x0409;
    emulator->string_table.strings = emulator->strings;
    emulator->device_strings[0] = &emulator->string_table;
    emulator->configuration = melodi_emulator_configuration;
    emulator->locator = 0;
    spin_lock_init(&emulator->lock);
    INIT_LIST_HEAD(&emulator->queue);
    INIT_WORK(&emulator->work, melodi_emulator_work);
    atomic_set(&emulator->transmit_count, 0);
    atomic_set(&emulator->packet_id, 1);
    melodi_radio_stream_init(&emulator->stream);
    emulator->function.name = "melodi-radio";
    emulator->function.strings = emulator->device_strings;
    emulator->function.bind = melodi_emulator_function_bind;
    emulator->function.unbind = melodi_emulator_function_unbind;
    emulator->function.set_alt = melodi_emulator_set_alt;
    emulator->function.disable = melodi_emulator_disable;
    emulator->function.mod = THIS_MODULE;
    emulator->driver.name = melodi_emulator_driver_names[index];
    emulator->driver.dev = &emulator->device;
    emulator->driver.strings = emulator->device_strings;
    emulator->driver.max_speed = USB_SPEED_HIGH;
    emulator->driver.bind = melodi_emulator_bind;
}

static int __init melodi_emulator_init(void)
{
    unsigned int index;
    int error;

    for (index = 0; index < ARRAY_SIZE(melodi_emulators); index++)
        melodi_emulator_initialize(&melodi_emulators[index], index);
    melodi_emulators[0].peer = &melodi_emulators[1];
    melodi_emulators[1].peer = &melodi_emulators[0];
    for (index = 0; index < ARRAY_SIZE(melodi_emulators); index++) {
        error = usb_composite_probe(&melodi_emulators[index].driver);
        if (error)
            goto unregister;
    }
    return 0;
unregister:
    while (index--)
        usb_composite_unregister(&melodi_emulators[index].driver);
    return error;
}

static void __exit melodi_emulator_exit(void)
{
    unsigned int index = ARRAY_SIZE(melodi_emulators);

    while (index--)
        usb_composite_unregister(&melodi_emulators[index].driver);
}

module_init(melodi_emulator_init);
module_exit(melodi_emulator_exit);

MODULE_AUTHOR("Melodi contributors");
MODULE_DESCRIPTION("Melodi bridged USB radio test emulator");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1.0");
