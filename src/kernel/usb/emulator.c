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
#include "meshtastic.h"

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
    struct melodi_mesh_stream stream;
    u32 node_number;
    bool enabled;
};

static struct melodi_emulator melodi_emulators[2];
static bool near_miss;
static bool firmware_refusal;
static bool unsafe_configuration;
static bool pause_handshake;
static bool malformed_protobuf;
module_param(near_miss, bool, 0444);
module_param(firmware_refusal, bool, 0444);
module_param(unsafe_configuration, bool, 0444);
module_param(pause_handshake, bool, 0444);
module_param(malformed_protobuf, bool, 0444);

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

static const u8 melodi_emulator_metadata[] = {
    0x6a, 0x17, 0x0a, 0x11, 'm', 'e', 'l', 'o', 'd', 'i', '-', 'u',
    's', 'b', '-', 't', 'e', 's', 't', '-', '1', 0x10, 0x01, 0x48, 0x01,
};

static const u8 melodi_emulator_bad_metadata[] = {
    0x6a, 0x17, 0x0a, 0x11, 'u', 'n', 's', 'u', 'p', 'p', 'o', 'r',
    't', 'e', 'd', '-', 'r', 'a', 'd', 'i', 'o', 0x10, 0x01, 0x48, 0x01,
};

static const u8 melodi_emulator_channel[] = {
    0x52, 0x04, 0x12, 0x00, 0x18, 0x01,
};

static const u8 melodi_emulator_lora[] = {
    0x2a, 0x11, 0x32, 0x0f, 0x08, 0x01, 0x10, 0x03, 0x38, 0x03,
    0x40, 0x03, 0x48, 0x01, 0x58, 0x07, 0xc0, 0x06, 0x01,
};

static const u8 melodi_emulator_unsafe_lora[] = {
    0x2a, 0x13, 0x32, 0x11, 0x08, 0x01, 0x10, 0x03, 0x38, 0x03,
    0x40, 0x03, 0x48, 0x01, 0x58, 0x07, 0x60, 0x01, 0xc0, 0x06, 0x01,
};

static const u8 melodi_emulator_mqtt[] = {
    0x4a, 0x02, 0x0a, 0x00,
};

static const u8 melodi_emulator_config_complete[] = {
    0x38, 0xac, 0x9e, 0x04,
};

static const u8 melodi_emulator_nodes_complete[] = {
    0x38, 0xad, 0x9e, 0x04,
};

static const u8 melodi_emulator_queue_status[] = {
    0x5a, 0x04, 0x10, 0x08, 0x18, 0x08,
};

static const u8 melodi_emulator_malformed[] = { 0x80 };

static void melodi_emulator_transmit_complete(struct usb_ep *endpoint,
                                              struct usb_request *request)
{
    struct melodi_emulator *emulator = request->context;

    kfree(request->buf);
    usb_ep_free_request(endpoint, request);
    atomic_dec(&emulator->transmit_count);
}

static int melodi_emulator_queue_records(struct melodi_emulator *emulator,
                                         const void *const *messages,
                                         const size_t *lengths, size_t count)
{
    struct usb_request *request;
    size_t total = 0;
    size_t framed_length;
    size_t offset = 0;
    size_t index;
    int error;

    if (!READ_ONCE(emulator->enabled) || !messages || !lengths || !count)
        return -ENETDOWN;
    for (index = 0; index < count; index++) {
        if (!messages[index] || !lengths[index] ||
            lengths[index] > MELODI_MESH_STREAM_MAX ||
            lengths[index] > MELODI_EMULATOR_BUFFER - 4 ||
            total > MELODI_EMULATOR_BUFFER - (lengths[index] + 4))
            return -EMSGSIZE;
        total += lengths[index] + 4;
    }
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
    request->buf = kmalloc(total, GFP_KERNEL);
    if (!request->buf) {
        error = -ENOMEM;
        goto free_request;
    }
    for (index = 0; index < count; index++) {
        error = melodi_mesh_stream_encode(
            messages[index], lengths[index], (u8 *)request->buf + offset,
            total - offset, &framed_length);
        if (error)
            goto free_buffer;
        offset += framed_length;
    }
    request->length = offset;
    request->complete = melodi_emulator_transmit_complete;
    request->context = emulator;
    error = usb_ep_queue(emulator->in_endpoint, request, GFP_KERNEL);
    if (!error)
        return 0;
free_buffer:
    kfree(request->buf);
free_request:
    usb_ep_free_request(emulator->in_endpoint, request);
decrement:
    atomic_dec(&emulator->transmit_count);
    return error;
}

static int melodi_emulator_queue_message(struct melodi_emulator *emulator,
                                         const void *message, size_t length)
{
    const void *messages[] = { message };
    const size_t lengths[] = { length };

    return melodi_emulator_queue_records(emulator, messages, lengths,
                                         ARRAY_SIZE(messages));
}

static int melodi_emulator_send_configuration(
    struct melodi_emulator *emulator)
{
    u8 my_info[16];
    size_t my_info_length;
    const void *messages[] = {
        my_info,
        firmware_refusal ? melodi_emulator_bad_metadata :
                           melodi_emulator_metadata,
        melodi_emulator_channel,
        unsafe_configuration ? melodi_emulator_unsafe_lora :
                               melodi_emulator_lora,
        melodi_emulator_mqtt,
        melodi_emulator_config_complete,
    };
    size_t lengths[] = {
        0,
        firmware_refusal ? sizeof(melodi_emulator_bad_metadata) :
                           sizeof(melodi_emulator_metadata),
        sizeof(melodi_emulator_channel),
        unsafe_configuration ? sizeof(melodi_emulator_unsafe_lora) :
                               sizeof(melodi_emulator_lora),
        sizeof(melodi_emulator_mqtt),
        sizeof(melodi_emulator_config_complete),
    };
    size_t count = ARRAY_SIZE(messages) - pause_handshake;
    int error;

    if (malformed_protobuf)
        return melodi_emulator_queue_message(
            emulator, melodi_emulator_malformed,
            sizeof(melodi_emulator_malformed));
    error = melodi_mesh_encode_my_info(
        READ_ONCE(emulator->node_number), my_info, sizeof(my_info),
        &my_info_length);
    if (error)
        return error;
    lengths[0] = my_info_length;
    return melodi_emulator_queue_records(emulator, messages, lengths, count);
}

static int melodi_emulator_handle_command(
    struct melodi_emulator *emulator,
    const struct melodi_mesh_command *command)
{
    struct melodi_emulator *peer = emulator->peer;
    struct melodi_mesh_packet packet;
    u8 message[MELODI_MESH_STREAM_MAX];
    u32 destination;
    u32 source;
    size_t length;
    int error;

    if (command->type == MELODI_MESH_COMMAND_CONFIG_REQUEST) {
        if (command->value == MELODI_MESH_CONFIG_NONCE)
            return melodi_emulator_send_configuration(emulator);
        if (command->value == MELODI_MESH_NODES_NONCE)
            return melodi_emulator_queue_message(
                emulator, melodi_emulator_nodes_complete,
                sizeof(melodi_emulator_nodes_complete));
        return -EPROTO;
    }
    if (command->type == MELODI_MESH_COMMAND_HEARTBEAT)
        return melodi_emulator_queue_message(
            emulator, melodi_emulator_queue_status,
            sizeof(melodi_emulator_queue_status));
    if (command->type == MELODI_MESH_COMMAND_DISCONNECT)
        return 0;
    if (command->type != MELODI_MESH_COMMAND_PACKET)
        return -EOPNOTSUPP;
    source = READ_ONCE(emulator->node_number);
    destination = READ_ONCE(peer->node_number);
    if (!source || !destination ||
        (command->packet.to != destination &&
         command->packet.to != MELODI_MESH_BROADCAST))
        return -EHOSTUNREACH;
    packet = command->packet;
    packet.from = source;
    packet.transport = 1;
    error = melodi_mesh_encode_from_radio(&packet, message, sizeof(message),
                                          &length);
    if (!error)
        error = melodi_emulator_queue_message(peer, message, length);
    if (!error && command->packet.want_ack) {
        u32 packet_id = atomic_inc_return(&peer->packet_id);

        if (!packet_id)
            packet_id = atomic_inc_return(&peer->packet_id);
        error = melodi_mesh_encode_routing_response(
            destination, source, packet_id,
            command->packet.id, 0, message, sizeof(message), &length);
        if (!error)
            error = melodi_emulator_queue_message(emulator, message, length);
    }
    return error;
}

static void melodi_emulator_parse(struct melodi_emulator *emulator,
                                  const struct melodi_emulator_chunk *chunk)
{
    struct melodi_mesh_command command;
    const u8 *message;
    size_t length;
    unsigned int index;
    int result;

    for (index = 0; index < chunk->length; index++) {
        result = melodi_mesh_stream_feed(&emulator->stream,
                                         chunk->data[index], &message,
                                         &length);
        if (result < 0) {
            pr_err_ratelimited("melodi emulator stream: %d\n", result);
            continue;
        }
        if (!result)
            continue;
        result = melodi_mesh_decode_to_radio(message, length, &command);
        if (!result)
            result = melodi_emulator_handle_command(emulator, &command);
        if (result)
            pr_err_ratelimited("melodi emulator command: %d\n", result);
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
    melodi_mesh_stream_init(&emulator->stream);
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
    emulator->node_number = 42 + index;
    spin_lock_init(&emulator->lock);
    INIT_LIST_HEAD(&emulator->queue);
    INIT_WORK(&emulator->work, melodi_emulator_work);
    atomic_set(&emulator->transmit_count, 0);
    atomic_set(&emulator->packet_id, 1);
    melodi_mesh_stream_init(&emulator->stream);
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
