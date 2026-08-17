/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/random.h>
#include <linux/refcount.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/tty.h>
#include <linux/tty_ldisc.h>
#include <linux/usb.h>
#include <linux/usb/cdc.h>
#include <linux/workqueue.h>

#include <melodi/core.h>
#include "contract.h"
#include "radio.h"

#define MELODI_USB_RX_URBS 4
#define MELODI_USB_RX_SIZE 512
#define MELODI_USB_RX_QUEUE_LIMIT 32
#define MELODI_USB_REASSEMBLY_LIMIT 8
#define MELODI_USB_REASSEMBLY_TIMEOUT (5 * HZ)
#define MELODI_USB_HANDSHAKE_TIMEOUT (15 * HZ)
#define MELODI_USB_ROUTING_TIMEOUT (30 * HZ)
#define MELODI_USB_ROUTING_LIMIT 64
#define MELODI_USB_IO_TIMEOUT 2000
#define MELODI_USB_TEST_ID 1
#define MELODI_USB_PICO_ID 2
#define MELODI_USB_STAGE_DELAY msecs_to_jiffies(100)
#define MELODI_TTY_LIMIT 16
#define MELODI_TTY_RECEIVE_ROOM 65536

static bool allow_test_device;
module_param(allow_test_device, bool, 0600);

static unsigned int radio_frequency_hz = 868100000;
static unsigned int radio_bandwidth_khz = 125;
static unsigned int radio_spreading_factor = 9;
static unsigned int radio_coding_rate = 5;
static int radio_transmit_power_dbm = 14;
static unsigned int radio_duty_permille = 100;
module_param_named(frequency, radio_frequency_hz, uint, 0644);
module_param_named(bandwidth, radio_bandwidth_khz, uint, 0644);
module_param_named(spreading, radio_spreading_factor, uint, 0644);
module_param_named(coding, radio_coding_rate, uint, 0644);
module_param_named(power, radio_transmit_power_dbm, int, 0644);
module_param_named(duty, radio_duty_permille, uint, 0644);

struct melodi_usb_device;
static struct usb_driver melodi_usb_driver;

struct melodi_usb_rx_chunk {
    struct list_head node;
    u16 length;
    u8 data[MELODI_USB_RX_SIZE];
};

struct melodi_usb_rx_slot {
    struct melodi_usb_device *device;
    struct urb *urb;
    u8 *buffer;
    dma_addr_t dma;
};

struct melodi_usb_tx {
    struct melodi_usb_device *device;
    struct sk_buff *frame;
    u64 cookie;
    atomic_t error;
    refcount_t references;
};

struct melodi_usb_route {
    struct melodi_usb_tx *transmit;
    unsigned long expires;
    u32 packet_id;
    bool active;
};

struct melodi_usb_reassembly {
    u8 *data;
    unsigned long expires;
    u32 source;
    u32 destination;
    u32 frame_id;
    u32 received;
    u16 total_length;
    u16 count;
    bool active;
};

struct melodi_usb_encode_batch {
    u8 segment[MELODI_RADIO_PACKET_MAX];
    u8 message[MELODI_RADIO_PAYLOAD_MAX];
    u32 packet_ids[MELODI_RADIO_SEGMENT_LIMIT];
};

struct melodi_usb_device {
    struct usb_device *usb;
    struct usb_interface *interface;
    struct usb_interface *data_interface;
    struct tty_struct *tty;
    struct net_device *netdev;
    struct usb_anchor rx_anchor;
    struct usb_anchor tx_anchor;
    struct melodi_usb_rx_slot rx_slots[MELODI_USB_RX_URBS];
    struct urb *control_urb;
    u8 *control_buffer;
    dma_addr_t control_dma;
    spinlock_t rx_lock;
    spinlock_t route_lock;
    struct list_head rx_queue;
    unsigned int rx_queued;
    struct workqueue_struct *workqueue;
    struct work_struct rx_work;
    struct work_struct config_work;
    struct delayed_work maintenance_work;
    struct mutex state_lock;
    struct mutex io_lock;
    struct melodi_radio_stream stream;
    struct melodi_usb_reassembly reassemblies[MELODI_USB_REASSEMBLY_LIMIT];
    struct melodi_usb_route routes[MELODI_USB_ROUTING_LIMIT];
    struct melodi_link_config desired;
    atomic_t frame_id;
    atomic_t packet_id;
    atomic_t io_error;
    atomic_t queue_free;
    atomic_t queue_maximum;
    unsigned long handshake_deadline;
    u32 local_locator;
    u32 assigned_locator;
    u16 packet_mtu;
    int failure;
    char firmware_version[32];
    char hardware_version[32];
    u8 bulk_in;
    u8 bulk_out;
    u8 profile;
    u8 fault;
    bool disconnected;
    bool suspended;
    bool ready;
    bool config_pending;
    bool failed;
    bool identified;
    bool pm_active;
    bool data_pm_active;
    bool direct_usb;
};

static DEFINE_MUTEX(melodi_tty_lock);
static struct tty_struct *melodi_ttys[MELODI_TTY_LIMIT];
static struct work_struct melodi_tty_reap_work;
static bool melodi_tty_ready;

static int melodi_usb_next_id(atomic_t *counter)
{
    int value = atomic_inc_return(counter);

    if (!value)
        value = atomic_inc_return(counter);
    return value;
}

static void melodi_usb_queue_release(struct melodi_usb_device *device,
                                     unsigned int count)
{
    int available;
    int maximum = atomic_read(&device->queue_maximum);
    int updated;

    if (!maximum)
        return;
    do {
        available = atomic_read(&device->queue_free);
        updated = min_t(int, maximum, available + (int)count);
    } while (atomic_cmpxchg(&device->queue_free, available, updated) !=
             available);
}

static int melodi_usb_queue_reserve(struct melodi_usb_device *device,
                                    unsigned int count)
{
    int available;

    do {
        available = atomic_read(&device->queue_free);
        if (available < 0 || (unsigned int)available < count)
            return -ENOBUFS;
    } while (atomic_cmpxchg(&device->queue_free, available,
                            available - count) != available);
    return 0;
}

static void melodi_usb_reassembly_clear(
    struct melodi_usb_reassembly *entry)
{
    kfree_sensitive(entry->data);
    memset(entry, 0, sizeof(*entry));
}

static void melodi_usb_reassembly_reset(struct melodi_usb_device *device)
{
    unsigned int index;

    for (index = 0; index < MELODI_USB_REASSEMBLY_LIMIT; index++)
        melodi_usb_reassembly_clear(&device->reassemblies[index]);
}

static void melodi_usb_rx_queue_clear(struct melodi_usb_device *device)
{
    struct melodi_usb_rx_chunk *chunk;
    struct melodi_usb_rx_chunk *next;
    LIST_HEAD(pending);
    unsigned long flags;

    spin_lock_irqsave(&device->rx_lock, flags);
    list_splice_init(&device->rx_queue, &pending);
    device->rx_queued = 0;
    spin_unlock_irqrestore(&device->rx_lock, flags);
    list_for_each_entry_safe(chunk, next, &pending, node) {
        list_del(&chunk->node);
        kfree(chunk);
    }
}

static void melodi_usb_fail(struct melodi_usb_device *device, int error,
                            enum melodi_link_failure failure,
                            const char *diagnostic)
{
    bool report = false;

    mutex_lock(&device->state_lock);
    if (!device->disconnected && !device->failed) {
        device->failed = true;
        device->ready = false;
        device->failure = error;
        report = true;
    }
    mutex_unlock(&device->state_lock);
    if (!report)
        return;
    melodi_link_failed(device->netdev, failure, error);
    dev_err(&device->interface->dev, "%s: %d\n", diagnostic, error);
}

static int melodi_usb_write_bytes(struct melodi_usb_device *device,
                                  const void *data, size_t length)
{
    unsigned long deadline;
    size_t offset = 0;
    unsigned int pipe;
    int actual = 0;
    int error = 0;

    if (!data || !length ||
        length > MELODI_RADIO_PAYLOAD_MAX + MELODI_RADIO_HEADER_SIZE)
        return -EINVAL;
    mutex_lock(&device->io_lock);
    if (READ_ONCE(device->disconnected)) {
        error = -ENODEV;
        goto unlock;
    }
    if (READ_ONCE(device->suspended)) {
        error = -EHOSTDOWN;
        goto unlock;
    }
    if (device->tty) {
        deadline = jiffies + msecs_to_jiffies(MELODI_USB_IO_TIMEOUT);
        set_bit(TTY_DO_WRITE_WAKEUP, &device->tty->flags);
        while (offset < length) {
            ssize_t written = device->tty->ops->write(
                device->tty, (const u8 *)data + offset, length - offset);

            if (written < 0) {
                error = written;
                break;
            }
            if (written > 0) {
                offset += written;
                continue;
            }
            if (time_after_eq(jiffies, deadline)) {
                error = -ETIMEDOUT;
                break;
            }
            wait_event_timeout(device->tty->write_wait,
                               tty_write_room(device->tty) > 0 ||
                               READ_ONCE(device->disconnected),
                               deadline - jiffies);
            if (READ_ONCE(device->disconnected)) {
                error = -ENODEV;
                break;
            }
        }
        clear_bit(TTY_DO_WRITE_WAKEUP, &device->tty->flags);
        goto unlock;
    }
    pipe = usb_sndbulkpipe(device->usb, device->bulk_out);
    error = usb_bulk_msg(device->usb, pipe, (void *)data, length, &actual,
                         MELODI_USB_IO_TIMEOUT);
    if (!error && actual != length)
        error = -EIO;
unlock:
    mutex_unlock(&device->io_lock);
    return error;
}


static void melodi_usb_tx_error(struct melodi_usb_tx *transmit, int error)
{
    if (error)
        atomic_cmpxchg(&transmit->error, 0, error);
}

static void melodi_usb_tx_put(struct melodi_usb_tx *transmit)
{
    if (!refcount_dec_and_test(&transmit->references))
        return;
    melodi_tx_complete(transmit->device->netdev, transmit->cookie,
                       atomic_read(&transmit->error));
    dev_kfree_skb_any(transmit->frame);
    kfree(transmit);
}

static int melodi_usb_route_admit(struct melodi_usb_device *device,
                                  struct melodi_usb_tx *transmit,
                                  const u32 *packet_ids, unsigned int count)
{
    unsigned long flags;
    unsigned int free = 0;
    unsigned int index;
    unsigned int packet;

    spin_lock_irqsave(&device->route_lock, flags);
    for (index = 0; index < MELODI_USB_ROUTING_LIMIT; index++) {
        if (!device->routes[index].active) {
            free++;
            continue;
        }
        for (packet = 0; packet < count; packet++)
            if (device->routes[index].packet_id == packet_ids[packet]) {
                spin_unlock_irqrestore(&device->route_lock, flags);
                return -EEXIST;
            }
    }
    if (free < count) {
        spin_unlock_irqrestore(&device->route_lock, flags);
        return -ENOSPC;
    }
    packet = 0;
    for (index = 0; index < MELODI_USB_ROUTING_LIMIT && packet < count;
         index++) {
        struct melodi_usb_route *route = &device->routes[index];

        if (route->active)
            continue;
        route->transmit = transmit;
        route->expires = jiffies + MELODI_USB_ROUTING_TIMEOUT;
        route->packet_id = packet_ids[packet++];
        route->active = true;
        refcount_inc(&transmit->references);
    }
    spin_unlock_irqrestore(&device->route_lock, flags);
    return 0;
}

static unsigned int melodi_usb_route_remove(
    struct melodi_usb_device *device, struct melodi_usb_tx *transmit)
{
    unsigned long flags;
    unsigned int count = 0;
    unsigned int index;

    spin_lock_irqsave(&device->route_lock, flags);
    for (index = 0; index < MELODI_USB_ROUTING_LIMIT; index++)
        if (device->routes[index].active &&
            device->routes[index].transmit == transmit) {
            memset(&device->routes[index], 0,
                   sizeof(device->routes[index]));
            count++;
        }
    spin_unlock_irqrestore(&device->route_lock, flags);
    return count;
}

static void melodi_usb_route_complete(struct melodi_usb_device *device,
                                      u32 packet_id, int error)
{
    struct melodi_usb_tx *transmit = NULL;
    unsigned long flags;
    unsigned int index;

    spin_lock_irqsave(&device->route_lock, flags);
    for (index = 0; index < MELODI_USB_ROUTING_LIMIT; index++)
        if (device->routes[index].active &&
            device->routes[index].packet_id == packet_id) {
            transmit = device->routes[index].transmit;
            memset(&device->routes[index], 0,
                   sizeof(device->routes[index]));
            break;
        }
    spin_unlock_irqrestore(&device->route_lock, flags);
    if (!transmit)
        return;
    melodi_usb_queue_release(device, 1);
    melodi_usb_tx_error(transmit, error);
    melodi_usb_tx_put(transmit);
}

static void melodi_usb_route_reset(struct melodi_usb_device *device, int error)
{
    struct melodi_usb_tx *transmit;
    unsigned long flags;
    unsigned int index;

    for (;;) {
        transmit = NULL;
        spin_lock_irqsave(&device->route_lock, flags);
        for (index = 0; index < MELODI_USB_ROUTING_LIMIT; index++)
            if (device->routes[index].active) {
                transmit = device->routes[index].transmit;
                memset(&device->routes[index], 0,
                       sizeof(device->routes[index]));
                break;
            }
        spin_unlock_irqrestore(&device->route_lock, flags);
        if (!transmit)
            return;
        melodi_usb_tx_error(transmit, error);
        melodi_usb_tx_put(transmit);
    }
}

static void melodi_usb_route_expire(struct melodi_usb_device *device)
{
    struct melodi_usb_tx *transmit;
    unsigned long flags;
    unsigned int index;

    for (;;) {
        transmit = NULL;
        spin_lock_irqsave(&device->route_lock, flags);
        for (index = 0; index < MELODI_USB_ROUTING_LIMIT; index++)
            if (device->routes[index].active &&
                time_after_eq(jiffies, device->routes[index].expires)) {
                transmit = device->routes[index].transmit;
                memset(&device->routes[index], 0,
                       sizeof(device->routes[index]));
                break;
            }
        spin_unlock_irqrestore(&device->route_lock, flags);
        if (!transmit)
            return;
        melodi_usb_queue_release(device, 1);
        melodi_usb_tx_error(transmit, -ETIMEDOUT);
        melodi_usb_tx_put(transmit);
    }
}


static int melodi_usb_xmit(struct net_device *netdev, struct sk_buff *frame,
                           const struct melodi_tx_meta *meta)
{
    struct melodi_usb_device *device = melodi_transport_priv(netdev);
    struct melodi_usb_encode_batch *batch;
    struct melodi_radio_segment segment = {};
    struct melodi_radio_transmit request = {};
    struct melodi_usb_tx *transmit;
    size_t segment_length;
    size_t message_length;
    unsigned int payload_mtu;
    unsigned int count;
    unsigned int index;
    u32 local_number;
    bool queue_reserved = false;
    bool route_admitted = false;
    int error;

    if (!device || !frame || !meta || !frame->len ||
        frame->len > MELODI_RADIO_FRAME_MAX)
        return -EINVAL;
    mutex_lock(&device->state_lock);
    local_number = device->local_locator;
    payload_mtu = device->packet_mtu > MELODI_RADIO_SEGMENT_SIZE ?
                  device->packet_mtu - MELODI_RADIO_SEGMENT_SIZE : 0;
    if (!device->ready || device->disconnected || device->suspended ||
        !payload_mtu || meta->source_locator != local_number) {
        mutex_unlock(&device->state_lock);
        return -ENETDOWN;
    }
    mutex_unlock(&device->state_lock);
    count = DIV_ROUND_UP(frame->len, payload_mtu);
    if (!count || count > MELODI_RADIO_SEGMENT_LIMIT)
        return -EMSGSIZE;
    error = melodi_usb_queue_reserve(device, count);
    if (error)
        return error;
    queue_reserved = true;
    transmit = kzalloc(sizeof(*transmit), GFP_KERNEL);
    batch = kzalloc(sizeof(*batch), GFP_KERNEL);
    if (!transmit || !batch) {
        error = -ENOMEM;
        goto free;
    }
    segment.frame_id = melodi_usb_next_id(&device->frame_id);
    segment.total_length = frame->len;
    segment.count = count;
    transmit->device = device;
    transmit->frame = frame;
    transmit->cookie = meta->cookie;
    atomic_set(&transmit->error, 0);
    refcount_set(&transmit->references, 1);
    for (index = 0; index < count; index++)
        batch->packet_ids[index] = melodi_usb_next_id(&device->packet_id);
    error = melodi_usb_route_admit(device, transmit, batch->packet_ids,
                                   count);
    if (error)
        goto free;
    route_admitted = true;
    for (index = 0; index < count; index++) {
        size_t offset = (size_t)index * payload_mtu;

        segment.index = index;
        segment.payload = frame->data + offset;
        segment.payload_length = min_t(size_t, frame->len - offset,
                                       payload_mtu);
        error = melodi_radio_segment_encode(&segment, batch->segment,
                                            sizeof(batch->segment),
                                            &segment_length);
        if (error)
            goto free;
        request.cookie = batch->packet_ids[index];
        request.destination = meta->destination_locator;
        request.payload = batch->segment;
        request.payload_length = (u16)segment_length;
        error = melodi_radio_encode_transmit(&request, batch->message,
                                             sizeof(batch->message),
                                             &message_length);
        if (error)
            goto free;
        error = melodi_usb_write_bytes(device, batch->message,
                                       message_length);
        if (error)
            goto free;
    }
    kfree(batch);
    melodi_usb_tx_put(transmit);
    return 0;

free:
    if (route_admitted) {
        unsigned int routes = melodi_usb_route_remove(device, transmit);

        melodi_usb_queue_release(device, routes);
        while (routes--)
            refcount_dec(&transmit->references);
    }
    if (queue_reserved && !route_admitted)
        melodi_usb_queue_release(device, count);
    kfree(transmit);
    kfree(batch);
    return error;
}

static int melodi_usb_configure(
    struct net_device *netdev, const struct melodi_link_config *config,
    struct netlink_ext_ack *extack)
{
    struct melodi_usb_device *device = melodi_transport_priv(netdev);

    (void)extack;
    if (!device || !config)
        return -EINVAL;
    mutex_lock(&device->state_lock);
    if (device->disconnected) {
        mutex_unlock(&device->state_lock);
        return -ENODEV;
    }
    device->desired = *config;
    device->config_pending = true;
    device->ready = false;
    mutex_unlock(&device->state_lock);
    melodi_link_ready(netdev, false, 0);
    melodi_usb_route_reset(device, -EKEYREVOKED);
    queue_work(device->workqueue, &device->config_work);
    return 0;
}

static void melodi_usb_get_info(struct net_device *netdev,
                                struct melodi_link_info *info)
{
    struct melodi_usb_device *device = melodi_transport_priv(netdev);

    info->abi_version = MELODI_CORE_ABI_VERSION;
    info->frame_mtu = MELODI_RADIO_FRAME_MAX < MELODI_FRAME_MTU_MAX ?
                      MELODI_RADIO_FRAME_MAX : MELODI_FRAME_MTU_MAX;
    strscpy(info->driver_version, "usb-0.1.0",
            sizeof(info->driver_version));
    if (device) {
        mutex_lock(&device->state_lock);
        strscpy(info->firmware_version, device->firmware_version,
                sizeof(info->firmware_version));
        mutex_unlock(&device->state_lock);
        usb_make_path(device->usb, info->bus_info, sizeof(info->bus_info));
    }
    if (!device || READ_ONCE(device->disconnected))
        info->state = MELODI_LINK_DISCONNECTED;
    else if (READ_ONCE(device->ready))
        info->state = MELODI_LINK_READY;
    else if (READ_ONCE(device->failed))
        info->state = MELODI_LINK_FAILED;
    else
        info->state = MELODI_LINK_CONFIGURING;
}

static int melodi_usb_airtime(struct net_device *netdev,
                              const struct sk_buff *frame,
                              const struct melodi_tx_meta *meta,
                              struct melodi_airtime_charge *charge)
{
    struct melodi_usb_device *device = melodi_transport_priv(netdev);
    unsigned int payload_mtu;
    unsigned int segments;
    u32 packet_us = 0;
    u16 packet_mtu;
    int error;

    (void)meta;
    if (!device || !frame || !charge)
        return -EINVAL;
    mutex_lock(&device->state_lock);
    packet_mtu = device->packet_mtu;
    mutex_unlock(&device->state_lock);
    if (packet_mtu <= MELODI_RADIO_SEGMENT_SIZE)
        return -ENETDOWN;
    payload_mtu = packet_mtu - MELODI_RADIO_SEGMENT_SIZE;
    segments = DIV_ROUND_UP(frame->len, payload_mtu);
    if (!segments || segments > MELODI_RADIO_SEGMENT_LIMIT)
        return -EMSGSIZE;
    error = melodi_radio_airtime_estimate(
        (u8)radio_spreading_factor, (u16)radio_bandwidth_khz,
        (u8)radio_coding_rate, packet_mtu, &packet_us);
    if (error)
        return error;
    charge->duration_us = (u64)packet_us * segments;
    charge->budget_us = MELODI_AIRTIME_WINDOW_US * radio_duty_permille / 1000;
    charge->broadcast_budget_us = charge->budget_us / 10;
    return 0;
}

static const struct melodi_link_ops melodi_usb_link_ops = {
    .xmit = melodi_usb_xmit,
    .configure = melodi_usb_configure,
    .get_info = melodi_usb_get_info,
    .airtime = melodi_usb_airtime,
};

static void melodi_usb_receive(struct melodi_usb_device *device,
                               const u8 *data, size_t length)
{
    unsigned long flags;

    while (length) {
        struct melodi_usb_rx_chunk *chunk;
        struct melodi_usb_rx_chunk *tail;
        size_t count;

        spin_lock_irqsave(&device->rx_lock, flags);
        tail = list_empty(&device->rx_queue) ? NULL :
               list_last_entry(&device->rx_queue,
                               struct melodi_usb_rx_chunk, node);
        if (tail && tail->length < MELODI_USB_RX_SIZE) {
            count = min_t(size_t, length, MELODI_USB_RX_SIZE - tail->length);
            memcpy(tail->data + tail->length, data, count);
            tail->length += count;
            spin_unlock_irqrestore(&device->rx_lock, flags);
            data += count;
            length -= count;
            continue;
        }
        spin_unlock_irqrestore(&device->rx_lock, flags);
        count = min_t(size_t, length, MELODI_USB_RX_SIZE);
        chunk = kmalloc(sizeof(*chunk), GFP_ATOMIC);
        if (!chunk) {
            device->netdev->stats.rx_dropped++;
            return;
        }
        chunk->length = count;
        memcpy(chunk->data, data, count);
        spin_lock_irqsave(&device->rx_lock, flags);
        if (device->rx_queued < MELODI_USB_RX_QUEUE_LIMIT) {
            list_add_tail(&chunk->node, &device->rx_queue);
            device->rx_queued++;
            chunk = NULL;
        }
        spin_unlock_irqrestore(&device->rx_lock, flags);
        if (chunk) {
            device->netdev->stats.rx_dropped++;
            kfree(chunk);
        }
        data += count;
        length -= count;
    }
    queue_work(device->workqueue, &device->rx_work);
}

static void melodi_usb_rx_complete(struct urb *urb)
{
    struct melodi_usb_rx_slot *slot = urb->context;
    struct melodi_usb_device *device = slot->device;
    int error;

    if (!urb->status && urb->actual_length)
        melodi_usb_receive(device, slot->buffer, urb->actual_length);
    else if (urb->status && urb->status != -ENOENT &&
               urb->status != -ECONNRESET && urb->status != -ESHUTDOWN) {
        atomic_cmpxchg(&device->io_error, 0, urb->status);
        queue_work(device->workqueue, &device->rx_work);
    }
    if (READ_ONCE(device->disconnected) || READ_ONCE(device->suspended))
        return;
    usb_anchor_urb(urb, &device->rx_anchor);
    error = usb_submit_urb(urb, GFP_ATOMIC);
    if (error) {
        usb_unanchor_urb(urb);
        atomic_cmpxchg(&device->io_error, 0, error);
        queue_work(device->workqueue, &device->rx_work);
    }
}

static void melodi_usb_control_complete(struct urb *urb)
{
    struct melodi_usb_device *device = urb->context;
    int error;

    if (urb->status && urb->status != -ENOENT &&
        urb->status != -ECONNRESET && urb->status != -ESHUTDOWN) {
        atomic_cmpxchg(&device->io_error, 0, urb->status);
        queue_work(device->workqueue, &device->rx_work);
    }
    if (READ_ONCE(device->disconnected) || READ_ONCE(device->suspended))
        return;
    usb_anchor_urb(urb, &device->rx_anchor);
    error = usb_submit_urb(urb, GFP_ATOMIC);
    if (!error)
        return;
    usb_unanchor_urb(urb);
    atomic_cmpxchg(&device->io_error, 0, error);
    queue_work(device->workqueue, &device->rx_work);
}

static int melodi_usb_submit_rx(struct melodi_usb_rx_slot *slot,
                                gfp_t allocation)
{
    struct melodi_usb_device *device = slot->device;
    int error;

    usb_anchor_urb(slot->urb, &device->rx_anchor);
    error = usb_submit_urb(slot->urb, allocation);
    if (error)
        usb_unanchor_urb(slot->urb);
    return error;
}

static int melodi_usb_submit_all_rx(struct melodi_usb_device *device)
{
    unsigned int index;
    int error;

    if (device->control_urb) {
        usb_anchor_urb(device->control_urb, &device->rx_anchor);
        error = usb_submit_urb(device->control_urb, GFP_KERNEL);
        if (error) {
            usb_unanchor_urb(device->control_urb);
            return error;
        }
    }
    for (index = 0; index < MELODI_USB_RX_URBS; index++) {
        error = melodi_usb_submit_rx(&device->rx_slots[index], GFP_KERNEL);
        if (error) {
            usb_kill_anchored_urbs(&device->rx_anchor);
            return error;
        }
    }
    return 0;
}

static int melodi_usb_cdc_set_line(struct melodi_usb_device *device)
{
    struct usb_cdc_line_coding line = {
        .dwDTERate = cpu_to_le32(9600),
        .bDataBits = 8,
    };

    if (device->profile != MELODI_USB_CONTRACT_CDC)
        return 0;
    return usb_control_msg_send(
        device->usb, 0, USB_CDC_REQ_SET_LINE_CODING,
        USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE, 0,
        MELODI_USB_CDC_CONTROL_INTERFACE, &line, sizeof(line),
        USB_CTRL_SET_TIMEOUT, GFP_KERNEL);
}

static int melodi_usb_cdc_connect(struct melodi_usb_device *device)
{
    if (device->profile != MELODI_USB_CONTRACT_CDC)
        return 0;
    return usb_control_msg_send(
        device->usb, 0, USB_CDC_REQ_SET_CONTROL_LINE_STATE,
        USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
        USB_CDC_CTRL_DTR | USB_CDC_CTRL_RTS,
        MELODI_USB_CDC_CONTROL_INTERFACE, NULL, 0,
        USB_CTRL_SET_TIMEOUT, GFP_KERNEL);
}


static struct melodi_usb_reassembly *melodi_usb_reassembly_find(
    struct melodi_usb_device *device,
    const struct melodi_radio_receive *packet,
    const struct melodi_radio_segment *segment)
{
    struct melodi_usb_reassembly *empty = NULL;
    unsigned int index;

    for (index = 0; index < MELODI_USB_REASSEMBLY_LIMIT; index++) {
        struct melodi_usb_reassembly *entry = &device->reassemblies[index];

        if (entry->active && time_after_eq(jiffies, entry->expires))
            melodi_usb_reassembly_clear(entry);
        if (!entry->active && !empty)
            empty = entry;
        if (entry->active && entry->source == packet->source &&
            entry->frame_id == segment->frame_id)
            return entry;
    }
    return empty;
}

static int melodi_usb_receive_segment(
    struct melodi_usb_device *device,
    const struct melodi_radio_receive *packet)
{
    struct melodi_usb_reassembly *entry;
    struct melodi_radio_segment segment;
    struct melodi_rx_meta metadata = {};
    unsigned int payload_mtu;
    unsigned int complete_mask;
    size_t offset;
    int error;

    error = melodi_radio_segment_decode(packet->payload,
                                        packet->payload_length, &segment);
    if (error)
        return error;
    if (packet->destination != MELODI_RADIO_LOCATOR_BROADCAST &&
        packet->destination != device->local_locator)
        return -EHOSTUNREACH;
    payload_mtu = device->packet_mtu > MELODI_RADIO_SEGMENT_SIZE ?
                  device->packet_mtu - MELODI_RADIO_SEGMENT_SIZE : 0;
    if (!payload_mtu)
        return -ENETDOWN;
    entry = melodi_usb_reassembly_find(device, packet, &segment);
    if (!entry)
        return -ENOSPC;
    if (!entry->active) {
        entry->data = kmalloc(segment.total_length, GFP_KERNEL);
        if (!entry->data)
            return -ENOMEM;
        entry->active = true;
        entry->expires = jiffies + MELODI_USB_REASSEMBLY_TIMEOUT;
        entry->source = packet->source;
        entry->destination = packet->destination;
        entry->frame_id = segment.frame_id;
        entry->total_length = segment.total_length;
        entry->count = segment.count;
    } else if (entry->destination != packet->destination ||
               entry->total_length != segment.total_length ||
               entry->count != segment.count) {
        melodi_usb_reassembly_clear(entry);
        return -EPROTO;
    }
    offset = (size_t)segment.index * payload_mtu;
    if (entry->received & BIT(segment.index)) {
        if (!memcmp(entry->data + offset, segment.payload,
                    segment.payload_length))
            return -EALREADY;
        melodi_usb_reassembly_clear(entry);
        return -EPROTO;
    }
    memcpy(entry->data + offset, segment.payload, segment.payload_length);
    entry->received |= BIT(segment.index);
    complete_mask = segment.count == 32 ? 0xffffffffU :
                    BIT(segment.count) - 1;
    if (entry->received != complete_mask)
        return 0;
    metadata.timestamp_ns = ktime_get_ns();
    metadata.source_locator = packet->source;
    metadata.destination_locator = packet->destination;
    metadata.rssi = packet->rssi;
    metadata.snr = packet->snr;
    metadata.hops = packet->hops;
    error = melodi_rx_frame(device->netdev, entry->data,
                            entry->total_length, &metadata);
    melodi_usb_reassembly_clear(entry);
    return error;
}
static int melodi_usb_result_error(u8 result)
{
    switch (result) {
    case MELODI_RADIO_RESULT_SENT:
        return 0;
    case MELODI_RADIO_RESULT_BUSY:
        return -EAGAIN;
    case MELODI_RADIO_RESULT_TOO_LARGE:
        return -EMSGSIZE;
    case MELODI_RADIO_RESULT_NOT_READY:
        return -ENETDOWN;
    case MELODI_RADIO_RESULT_DUTY:
        return -EBUSY;
    default:
        return -EIO;
    }
}

static enum melodi_link_failure melodi_usb_fault_failure(u8 fault)
{
    switch (fault) {
    case MELODI_RADIO_FAULT_HARDWARE:
        return MELODI_LINK_FAILURE_MODEM;
    case MELODI_RADIO_FAULT_REGION:
        return MELODI_LINK_FAILURE_REGION;
    case MELODI_RADIO_FAULT_MODEM:
        return MELODI_LINK_FAILURE_MODEM;
    case MELODI_RADIO_FAULT_LOCATOR:
        return MELODI_LINK_FAILURE_NODE_NUMBER;
    case MELODI_RADIO_FAULT_DOMAIN:
        return MELODI_LINK_FAILURE_CHANNEL;
    case MELODI_RADIO_FAULT_OVERRUN:
        return MELODI_LINK_FAILURE_QUEUE_STATUS;
    default:
        return MELODI_LINK_FAILURE_INTERNAL;
    }
}

static int melodi_usb_send_configure(struct melodi_usb_device *device)
{
    struct melodi_radio_configure config = {};
    u8 message[MELODI_RADIO_PAYLOAD_MAX];
    size_t length;
    int error;

    mutex_lock(&device->state_lock);
    memcpy(config.domain, device->desired.mesh_domain,
           sizeof(config.domain));
    config.locator = device->assigned_locator;
    mutex_unlock(&device->state_lock);
    config.frequency_hz = radio_frequency_hz;
    config.bandwidth_khz = (u16)radio_bandwidth_khz;
    config.spreading_factor = (u8)radio_spreading_factor;
    config.coding_rate = (u8)radio_coding_rate;
    config.transmit_power_dbm = (s16)radio_transmit_power_dbm;
    config.duty_permille = (u16)radio_duty_permille;
    error = melodi_radio_encode_configure(&config, message, sizeof(message),
                                          &length);
    if (error)
        return error;
    return melodi_usb_write_bytes(device, message, length);
}

static void melodi_usb_handle_info(struct melodi_usb_device *device,
                                   const struct melodi_radio_info *info)
{
    int error;

    mutex_lock(&device->state_lock);
    device->packet_mtu = info->packet_mtu;
    device->identified = true;
    strscpy(device->firmware_version, info->firmware,
            sizeof(device->firmware_version));
    strscpy(device->hardware_version, info->hardware,
            sizeof(device->hardware_version));
    atomic_set(&device->queue_maximum, info->queue_depth);
    atomic_set(&device->queue_free, info->queue_depth);
    mutex_unlock(&device->state_lock);
    error = melodi_usb_send_configure(device);
    if (error)
        melodi_usb_fail(device, error, MELODI_LINK_FAILURE_TRANSPORT,
                        "radio configuration request");
}

static void melodi_usb_handle_status(struct melodi_usb_device *device,
                                     const struct melodi_radio_status *status)
{
    bool ready = false;
    u32 locator = 0;

    atomic_set(&device->queue_maximum, status->queue_depth);
    atomic_set(&device->queue_free, status->queue_free);
    if (status->state == MELODI_RADIO_STATE_FAILED) {
        melodi_usb_fail(device, -EPROTO,
                        melodi_usb_fault_failure(status->fault),
                        "radio reported a fault");
        return;
    }
    mutex_lock(&device->state_lock);
    device->fault = status->fault;
    if (status->state == MELODI_RADIO_STATE_READY && device->identified &&
        status->locator && status->locator == device->assigned_locator &&
        !device->ready && !device->failed) {
        device->ready = true;
        device->local_locator = status->locator;
        locator = status->locator;
        ready = true;
    }
    mutex_unlock(&device->state_lock);
    if (ready)
        melodi_link_ready(device->netdev, true, locator);
}

static void melodi_usb_handle_message(struct melodi_usb_device *device,
                                      const struct melodi_radio_header *header,
                                      const u8 *payload)
{
    struct melodi_radio_result_report report;
    struct melodi_radio_receive receive;
    struct melodi_radio_status status;
    struct melodi_radio_info info;
    int error;

    switch (header->type) {
    case MELODI_RADIO_T_INFO:
        error = melodi_radio_decode_info(payload, header->length, &info);
        if (!error)
            melodi_usb_handle_info(device, &info);
        break;
    case MELODI_RADIO_T_STATUS:
        error = melodi_radio_decode_status(payload, header->length, &status);
        if (!error)
            melodi_usb_handle_status(device, &status);
        break;
    case MELODI_RADIO_T_RECEIVE:
        error = melodi_radio_decode_receive(payload, header->length,
                                            &receive);
        if (!error && READ_ONCE(device->ready)) {
            error = melodi_usb_receive_segment(device, &receive);
            if (error == -EALREADY || error == -EHOSTUNREACH)
                error = 0;
            if (error)
                device->netdev->stats.rx_errors++;
            error = 0;
        }
        break;
    case MELODI_RADIO_T_RESULT:
        error = melodi_radio_decode_result(payload, header->length, &report);
        if (!error)
            melodi_usb_route_complete(
                device, report.cookie,
                melodi_usb_result_error(report.result));
        break;
    default:
        error = -EOPNOTSUPP;
        break;
    }
    if (error && error != -EOPNOTSUPP) {
        device->netdev->stats.rx_errors++;
        if (!READ_ONCE(device->ready))
            melodi_usb_fail(device, error, MELODI_LINK_FAILURE_PROTOBUF,
                            "radio message record");
    }
}


static void melodi_usb_parse_chunk(struct melodi_usb_device *device,
                                   const struct melodi_usb_rx_chunk *chunk)
{
    const struct melodi_radio_header *header;
    const u8 *payload;
    unsigned int index;
    int result;

    for (index = 0; index < chunk->length; index++) {
        result = melodi_radio_stream_feed(&device->stream, chunk->data[index],
                                          &header, &payload);
        if (result < 0) {
            device->netdev->stats.rx_errors++;
            if (!READ_ONCE(device->ready))
                melodi_usb_fail(device, result, MELODI_LINK_FAILURE_STREAM,
                                "radio stream framing");
            continue;
        }
        if (!result)
            continue;
        melodi_usb_handle_message(device, header, payload);
    }
}

static void melodi_usb_rx_work(struct work_struct *work)
{
    struct melodi_usb_device *device = container_of(
        work, struct melodi_usb_device, rx_work);
    struct melodi_usb_rx_chunk *chunk;
    unsigned long flags;
    int error;

    error = atomic_xchg(&device->io_error, 0);
    if (error)
        melodi_usb_fail(device, error, MELODI_LINK_FAILURE_TRANSPORT,
                        "USB receive endpoint");
    for (;;) {
        spin_lock_irqsave(&device->rx_lock, flags);
        chunk = list_first_entry_or_null(&device->rx_queue,
                                         struct melodi_usb_rx_chunk, node);
        if (chunk) {
            list_del(&chunk->node);
            device->rx_queued--;
        }
        spin_unlock_irqrestore(&device->rx_lock, flags);
        if (!chunk)
            break;
        melodi_usb_parse_chunk(device, chunk);
        kfree(chunk);
    }
}

static void melodi_usb_config_work(struct work_struct *work)
{
    struct melodi_usb_device *device = container_of(
        work, struct melodi_usb_device, config_work);
    u8 message[MELODI_RADIO_PAYLOAD_MAX];
    size_t length;
    int error;

    mutex_lock(&device->state_lock);
    if (!device->config_pending || device->disconnected ||
        device->suspended) {
        mutex_unlock(&device->state_lock);
        return;
    }
    device->config_pending = false;
    device->failed = false;
    device->failure = 0;
    device->ready = false;
    device->identified = false;
    device->fault = MELODI_RADIO_FAULT_NONE;
    atomic_set(&device->queue_free, 0);
    atomic_set(&device->queue_maximum, 0);
    device->local_locator = 0;
    device->packet_mtu = 0;
    device->assigned_locator = device->desired.locator;
    device->handshake_deadline = jiffies + MELODI_USB_HANDSHAKE_TIMEOUT;
    melodi_radio_stream_init(&device->stream);
    melodi_usb_reassembly_reset(device);
    mutex_unlock(&device->state_lock);
    if (!device->assigned_locator ||
        device->assigned_locator == MELODI_RADIO_LOCATOR_BROADCAST) {
        melodi_usb_fail(device, -EINVAL, MELODI_LINK_FAILURE_NODE_NUMBER,
                        "core supplied no usable locator");
        return;
    }
    error = melodi_radio_encode_reset(message, sizeof(message), &length);
    if (!error)
        error = melodi_usb_write_bytes(device, message, length);
    if (!error)
        error = melodi_radio_encode_identify(message, sizeof(message),
                                             &length);
    if (!error)
        error = melodi_usb_write_bytes(device, message, length);
    if (error) {
        melodi_usb_fail(device, error, MELODI_LINK_FAILURE_TRANSPORT,
                        "radio identify request");
        return;
    }
    queue_delayed_work(device->workqueue, &device->maintenance_work, HZ);
}

static void melodi_usb_maintenance_work(struct work_struct *work)
{
    struct melodi_usb_device *device = container_of(
        to_delayed_work(work), struct melodi_usb_device, maintenance_work);
    bool timeout;
    bool reschedule;
    unsigned int index;

    melodi_usb_route_expire(device);
    for (index = 0; index < MELODI_USB_REASSEMBLY_LIMIT; index++)
        if (device->reassemblies[index].active &&
            time_after_eq(jiffies, device->reassemblies[index].expires))
            melodi_usb_reassembly_clear(&device->reassemblies[index]);
    mutex_lock(&device->state_lock);
    timeout = !device->ready && !device->failed &&
              time_after_eq(jiffies, device->handshake_deadline);
    reschedule = !device->disconnected && !device->suspended;
    mutex_unlock(&device->state_lock);
    if (timeout)
        melodi_usb_fail(device, -ETIMEDOUT, MELODI_LINK_FAILURE_TIMEOUT,
                        "configuration handshake timeout");
    if (reschedule)
        queue_delayed_work(device->workqueue, &device->maintenance_work, HZ);
}

static int melodi_usb_validate_pico_control(struct usb_device *usb)
{
    struct usb_interface *interface = usb_ifnum_to_if(
        usb, MELODI_USB_CDC_CONTROL_INTERFACE);
    struct usb_host_interface *setting;
    struct usb_endpoint_descriptor *endpoint;

    if (!interface)
        return -ENODEV;
    setting = interface->cur_altsetting;
    if (setting->desc.bInterfaceNumber !=
            MELODI_USB_CDC_CONTROL_INTERFACE ||
        setting->desc.bAlternateSetting ||
        setting->desc.bInterfaceClass != MELODI_USB_CDC_CONTROL_CLASS ||
        setting->desc.bInterfaceSubClass !=
            MELODI_USB_CDC_CONTROL_SUBCLASS ||
        setting->desc.bInterfaceProtocol !=
            MELODI_USB_CDC_CONTROL_PROTOCOL ||
        setting->desc.bNumEndpoints != 1)
        return -ENODEV;
    endpoint = &setting->endpoint[0].desc;
    if (!usb_endpoint_is_int_in(endpoint) ||
        endpoint->bEndpointAddress != MELODI_USB_CDC_CONTROL_IN ||
        usb_endpoint_maxp(endpoint) != MELODI_USB_CDC_CONTROL_MAX_PACKET)
        return -ENODEV;
    return 0;
}

static int melodi_usb_validate_interface(struct usb_interface *interface,
                                         u8 profile, u8 *bulk_in,
                                         u8 *bulk_out, char *radio_serial,
                                         const char **stage)
{
    struct usb_host_interface *setting = interface->cur_altsetting;
    struct usb_device *usb = interface_to_usbdev(interface);
    struct melodi_usb_contract contract = {};
    char product[64];
    unsigned int index;
    int length;

    contract.interface_number = setting->desc.bInterfaceNumber;
    contract.alternate = setting->desc.bAlternateSetting;
    contract.interface_class = setting->desc.bInterfaceClass;
    contract.interface_subclass = setting->desc.bInterfaceSubClass;
    contract.interface_protocol = setting->desc.bInterfaceProtocol;
    contract.endpoint_count = setting->desc.bNumEndpoints;
    contract.vendor = le16_to_cpu(usb->descriptor.idVendor);
    contract.product_id = le16_to_cpu(usb->descriptor.idProduct);
    contract.device_version = le16_to_cpu(usb->descriptor.bcdDevice);
    contract.profile = profile;
    contract.full_speed = usb->speed == USB_SPEED_FULL;
    contract.high_speed = usb->speed == USB_SPEED_HIGH;
    *stage = "data interface contract";
    if (contract.endpoint_count != MELODI_USB_CONTRACT_ENDPOINTS)
        return -ENODEV;
    for (index = 0; index < contract.endpoint_count; index++) {
        struct usb_endpoint_descriptor *endpoint =
            &setting->endpoint[index].desc;

        contract.endpoints[index].address = endpoint->bEndpointAddress;
        contract.endpoints[index].attributes =
            endpoint->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
        contract.endpoints[index].max_packet = usb_endpoint_maxp(endpoint);
    }
    *stage = "USB identity strings";
    if (!usb->descriptor.iProduct || !usb->descriptor.iSerialNumber ||
        !usb->product || !usb->serial)
        return -ENODEV;
    length = strscpy(product, usb->product, sizeof(product));
    if (length < 0)
        return -ENODEV;
    contract.product = product;
    contract.product_length = length;
    length = strscpy(radio_serial, usb->serial,
                     MELODI_RADIO_SERIAL_MAX + 1);
    if (length <= 0)
        return -ENODEV;
    contract.serial = radio_serial;
    contract.serial_length = length;
    *stage = "USB data contract";
    if (melodi_usb_contract_validate(&contract))
        return -ENODEV;
    if (profile == MELODI_USB_CONTRACT_CDC) {
        *stage = "CDC control contract";
        if (melodi_usb_validate_pico_control(usb))
            return -ENODEV;
        *bulk_in = MELODI_USB_CDC_IN;
        *bulk_out = MELODI_USB_CDC_OUT;
    } else {
        *bulk_in = MELODI_USB_TEST_IN;
        *bulk_out = MELODI_USB_TEST_OUT;
    }
    return 0;
}

static int melodi_usb_allocate_rx(struct melodi_usb_device *device)
{
    struct usb_endpoint_descriptor *control_endpoint;
    unsigned int index;

    if (!device->direct_usb)
        return 0;
    if (device->profile == MELODI_USB_CONTRACT_CDC) {
        control_endpoint =
            &device->interface->cur_altsetting->endpoint[0].desc;
        device->control_urb = usb_alloc_urb(0, GFP_KERNEL);
        device->control_buffer = usb_alloc_coherent(
            device->usb, MELODI_USB_CDC_CONTROL_MAX_PACKET, GFP_KERNEL,
            &device->control_dma);
        if (!device->control_urb || !device->control_buffer)
            return -ENOMEM;
        usb_fill_int_urb(
            device->control_urb, device->usb,
            usb_rcvintpipe(device->usb, MELODI_USB_CDC_CONTROL_IN),
            device->control_buffer, MELODI_USB_CDC_CONTROL_MAX_PACKET,
            melodi_usb_control_complete, device,
            control_endpoint->bInterval ?: 16);
        device->control_urb->transfer_dma = device->control_dma;
        device->control_urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
    }
    for (index = 0; index < MELODI_USB_RX_URBS; index++) {
        struct melodi_usb_rx_slot *slot = &device->rx_slots[index];

        slot->device = device;
        slot->urb = usb_alloc_urb(0, GFP_KERNEL);
        slot->buffer = usb_alloc_coherent(device->usb, MELODI_USB_RX_SIZE,
                                          GFP_KERNEL, &slot->dma);
        if (!slot->urb || !slot->buffer)
            return -ENOMEM;
        usb_fill_bulk_urb(slot->urb, device->usb,
                          usb_rcvbulkpipe(device->usb, device->bulk_in),
                          slot->buffer, MELODI_USB_RX_SIZE,
                          melodi_usb_rx_complete, slot);
        slot->urb->transfer_dma = slot->dma;
        slot->urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
    }
    return 0;
}

static void melodi_usb_free_rx(struct melodi_usb_device *device)
{
    unsigned int index;

    if (!device->direct_usb)
        return;
    for (index = 0; index < MELODI_USB_RX_URBS; index++) {
        struct melodi_usb_rx_slot *slot = &device->rx_slots[index];

        usb_free_urb(slot->urb);
        if (slot->buffer)
            usb_free_coherent(device->usb, MELODI_USB_RX_SIZE,
                              slot->buffer, slot->dma);
        slot->urb = NULL;
        slot->buffer = NULL;
    }
    usb_free_urb(device->control_urb);
    if (device->control_buffer)
        usb_free_coherent(device->usb,
                          MELODI_USB_CDC_CONTROL_MAX_PACKET,
                          device->control_buffer, device->control_dma);
    device->control_urb = NULL;
    device->control_buffer = NULL;
}

static int melodi_usb_state_init(struct melodi_usb_device *device)
{
    int error;

    init_usb_anchor(&device->rx_anchor);
    init_usb_anchor(&device->tx_anchor);
    spin_lock_init(&device->rx_lock);
    spin_lock_init(&device->route_lock);
    INIT_LIST_HEAD(&device->rx_queue);
    mutex_init(&device->state_lock);
    mutex_init(&device->io_lock);
    atomic_set(&device->frame_id, get_random_u32());
    atomic_set(&device->packet_id, get_random_u32());
    atomic_set(&device->io_error, 0);
    atomic_set(&device->queue_free, 0);
    atomic_set(&device->queue_maximum, 0);
    melodi_radio_stream_init(&device->stream);
    INIT_WORK(&device->rx_work, melodi_usb_rx_work);
    INIT_WORK(&device->config_work, melodi_usb_config_work);
    INIT_DELAYED_WORK(&device->maintenance_work,
                      melodi_usb_maintenance_work);
    device->workqueue = alloc_ordered_workqueue("melodi_usb",
                                                WQ_MEM_RECLAIM);
    if (!device->workqueue)
        return -ENOMEM;
    error = melodi_usb_allocate_rx(device);
    if (!error)
        return 0;
    melodi_usb_free_rx(device);
    destroy_workqueue(device->workqueue);
    device->workqueue = NULL;
    return error;
}

static int melodi_usb_probe(struct usb_interface *interface,
                            const struct usb_device_id *identifier)
{
    struct melodi_usb_device *device;
    struct usb_interface *data_interface = interface;
    struct net_device *netdev;
    struct usb_device *usb = interface_to_usbdev(interface);
    char radio_serial[MELODI_RADIO_SERIAL_MAX + 1];
    u8 bulk_in;
    u8 bulk_out;
    const char *stage = "device validation";
    bool data_claimed = false;
    int error;

    if (identifier->driver_info != MELODI_USB_TEST_ID &&
        identifier->driver_info != MELODI_USB_PICO_ID) {
        error = -ENODEV;
        goto report;
    }
    if (identifier->driver_info == MELODI_USB_TEST_ID &&
        !allow_test_device) {
        error = -ENODEV;
        goto report;
    }
    if (identifier->driver_info == MELODI_USB_PICO_ID) {
        stage = "CDC data interface lookup";
        data_interface = usb_ifnum_to_if(usb, MELODI_USB_CDC_INTERFACE);
        if (!data_interface || data_interface == interface) {
            error = -ENODEV;
            goto report;
        }
    }
    error = melodi_usb_validate_interface(
        data_interface, identifier->driver_info == MELODI_USB_TEST_ID ?
                            MELODI_USB_CONTRACT_TEST :
                            MELODI_USB_CONTRACT_CDC,
        &bulk_in, &bulk_out, radio_serial, &stage);
    if (error)
        goto report;
    stage = "transport selection";
    netdev = melodi_attach_selected_transport(
        &interface->dev, radio_serial, sizeof(*device),
        &melodi_usb_link_ops, THIS_MODULE);
    if (IS_ERR(netdev)) {
        error = PTR_ERR(netdev);
        goto report;
    }
    device = melodi_transport_priv(netdev);
    device->usb = usb_get_dev(usb);
    device->interface = interface;
    device->data_interface = data_interface;
    device->netdev = netdev;
    device->bulk_in = bulk_in;
    device->bulk_out = bulk_out;
    device->profile = identifier->driver_info == MELODI_USB_TEST_ID ?
                      MELODI_USB_CONTRACT_TEST :
                      MELODI_USB_CONTRACT_CDC;
    device->direct_usb = true;
    stage = "transport allocation";
    error = melodi_usb_state_init(device);
    if (error)
        goto detach;
    usb_set_intfdata(interface, device);
    if (data_interface != interface) {
        stage = "CDC data interface claim";
        error = usb_driver_claim_interface(&melodi_usb_driver,
                                           data_interface, device);
        if (error)
            goto clear_interface;
        data_claimed = true;
    }
    stage = "USB runtime activation";
    error = usb_autopm_get_interface(interface);
    if (error)
        goto clear_interface;
    device->pm_active = true;
    if (data_interface != interface) {
        error = usb_autopm_get_interface(data_interface);
        if (error)
            goto clear_interface;
        device->data_pm_active = true;
    }
    stage = "receive submission";
    error = melodi_usb_submit_all_rx(device);
    if (error)
        goto clear_interface;
    stage = "CDC line coding";
    error = melodi_usb_cdc_set_line(device);
    if (error)
        goto kill_rx;
    stage = "CDC host connection";
    error = melodi_usb_cdc_connect(device);
    if (error)
        goto kill_rx;
    stage = "transport configuration";
    error = melodi_transport_configure(netdev);
    if (error == -EAGAIN)
        error = 0;
    if (error)
        goto kill_rx;
    return 0;

kill_rx:
    usb_kill_anchored_urbs(&device->rx_anchor);
clear_interface:
    if (device->data_pm_active) {
        device->data_pm_active = false;
        usb_autopm_put_interface(data_interface);
    }
    if (device->pm_active) {
        device->pm_active = false;
        usb_autopm_put_interface(interface);
    }
    usb_set_intfdata(interface, NULL);
    if (data_claimed) {
        usb_set_intfdata(data_interface, NULL);
        usb_driver_release_interface(&melodi_usb_driver, data_interface);
    }
    WRITE_ONCE(device->disconnected, true);
    melodi_usb_free_rx(device);
    destroy_workqueue(device->workqueue);
detach:
    usb_put_dev(device->usb);
    melodi_detach_transport(netdev);
report:
    dev_err(&interface->dev, "probe failed at %s: %d\n", stage, error);
    return error;
}

static void melodi_usb_quiesce(struct melodi_usb_device *device,
                               bool disconnect)
{
    mutex_lock(&device->state_lock);
    if (disconnect)
        device->disconnected = true;
    device->suspended = true;
    device->ready = false;
    atomic_set(&device->queue_free, 0);
    atomic_set(&device->queue_maximum, 0);
    mutex_unlock(&device->state_lock);
    melodi_link_ready(device->netdev, false, 0);
    mutex_lock(&device->io_lock);
    usb_kill_anchored_urbs(&device->tx_anchor);
    usb_kill_anchored_urbs(&device->rx_anchor);
    mutex_unlock(&device->io_lock);
    melodi_usb_route_reset(device, -ENETDOWN);
    cancel_delayed_work_sync(&device->maintenance_work);
    flush_workqueue(device->workqueue);
    melodi_usb_rx_queue_clear(device);
    melodi_usb_reassembly_reset(device);
}

static void melodi_usb_disconnect(struct usb_interface *interface)
{
    struct melodi_usb_device *device = usb_get_intfdata(interface);
    struct usb_interface *other;
    struct net_device *netdev;
    struct usb_device *usb;

    if (!device)
        return;
    other = interface == device->interface ? device->data_interface :
                                             device->interface;
    usb_set_intfdata(device->interface, NULL);
    usb_set_intfdata(device->data_interface, NULL);
    if (other != interface &&
        other->dev.driver == &melodi_usb_driver.driver)
        usb_driver_release_interface(&melodi_usb_driver, other);
    netdev = device->netdev;
    usb = device->usb;
    melodi_usb_quiesce(device, true);
    if (device->data_pm_active) {
        device->data_pm_active = false;
        usb_autopm_put_interface_no_suspend(device->data_interface);
    }
    if (device->pm_active) {
        device->pm_active = false;
        usb_autopm_put_interface_no_suspend(device->interface);
    }
    melodi_usb_free_rx(device);
    destroy_workqueue(device->workqueue);
    melodi_detach_transport(netdev);
    usb_put_dev(usb);
}

static int melodi_usb_suspend(struct usb_interface *interface,
                              pm_message_t message)
{
    struct melodi_usb_device *device = usb_get_intfdata(interface);

    (void)message;
    if (!device || interface != device->interface)
        return 0;
    melodi_usb_quiesce(device, false);
    return 0;
}

static int melodi_usb_resume(struct usb_interface *interface)
{
    struct melodi_usb_device *device = usb_get_intfdata(interface);
    int error;

    if (!device || interface != device->interface)
        return 0;
    mutex_lock(&device->state_lock);
    device->suspended = false;
    device->config_pending = true;
    device->failed = false;
    melodi_radio_stream_init(&device->stream);
    mutex_unlock(&device->state_lock);
    error = melodi_usb_submit_all_rx(device);
    if (error) {
        melodi_usb_fail(device, error, MELODI_LINK_FAILURE_TRANSPORT,
                        "USB resume receive endpoint");
        return error;
    }
    error = melodi_usb_cdc_set_line(device);
    if (!error)
        error = melodi_usb_cdc_connect(device);
    if (error) {
        usb_kill_anchored_urbs(&device->rx_anchor);
        melodi_usb_fail(device, error, MELODI_LINK_FAILURE_TRANSPORT,
                        "USB resume CDC connection");
        return error;
    }
    error = melodi_transport_configure(device->netdev);
    if (error == -EAGAIN)
        return 0;
    return error;
}

static int melodi_usb_pre_reset(struct usb_interface *interface)
{
    return melodi_usb_suspend(interface, PMSG_SUSPEND);
}

static int melodi_usb_post_reset(struct usb_interface *interface)
{
    return melodi_usb_resume(interface);
}

static void melodi_usb_shutdown(struct usb_interface *interface)
{
    struct melodi_usb_device *device = usb_get_intfdata(interface);

    if (device && interface == device->interface)
        melodi_link_ready(device->netdev, false, 0);
}

static int melodi_tty_open(struct tty_struct *tty)
{
    struct melodi_usb_device *device;
    struct usb_interface *control_interface;
    struct usb_interface *data_interface;
    struct net_device *netdev;
    struct usb_device *usb;
    struct device *parent = tty->dev ? tty->dev->parent : NULL;
    char radio_serial[MELODI_RADIO_SERIAL_MAX + 1];
    const char *stage = "TTY device contract";
    u8 bulk_in;
    u8 bulk_out;
    int error;

    if (!capable(CAP_NET_ADMIN))
        return -EPERM;
    if (!tty->ops->write || !parent || !parent->bus ||
        strcmp(parent->bus->name, "usb"))
        return -ENODEV;
    control_interface = to_usb_interface(parent);
    usb = interface_to_usbdev(control_interface);
    data_interface = usb_ifnum_to_if(usb, MELODI_USB_CDC_INTERFACE);
    if (!data_interface || data_interface == control_interface)
        return -ENODEV;
    error = melodi_usb_validate_interface(
        data_interface, MELODI_USB_CONTRACT_CDC, &bulk_in, &bulk_out,
        radio_serial, &stage);
    if (error)
        return error;
    netdev = melodi_attach_selected_transport(
        tty->dev, radio_serial, sizeof(*device), &melodi_usb_link_ops,
        THIS_MODULE);
    if (IS_ERR(netdev))
        return PTR_ERR(netdev);
    device = melodi_transport_priv(netdev);
    device->usb = usb_get_dev(usb);
    device->interface = control_interface;
    device->data_interface = data_interface;
    device->tty = tty;
    device->netdev = netdev;
    device->bulk_in = bulk_in;
    device->bulk_out = bulk_out;
    device->profile = MELODI_USB_CONTRACT_CDC;
    error = melodi_usb_state_init(device);
    if (error)
        goto detach;
    tty->receive_room = MELODI_TTY_RECEIVE_ROOM;
    tty->disc_data = device;
    error = melodi_transport_configure(netdev);
    if (error == -EAGAIN)
        error = 0;
    if (!error)
        return 0;
    tty->disc_data = NULL;
    destroy_workqueue(device->workqueue);
detach:
    usb_put_dev(device->usb);
    melodi_detach_transport(netdev);
    return error;
}

static void melodi_tty_close(struct tty_struct *tty)
{
    struct melodi_usb_device *device = tty->disc_data;
    struct net_device *netdev;
    struct usb_device *usb;

    if (!device)
        return;
    netdev = device->netdev;
    usb = device->usb;
    melodi_usb_quiesce(device, true);
    tty->disc_data = NULL;
    destroy_workqueue(device->workqueue);
    melodi_detach_transport(netdev);
    usb_put_dev(usb);
}

static void melodi_tty_receive_buf(struct tty_struct *tty, const u8 *data,
                                   const u8 *flags, size_t length)
{
    struct melodi_usb_device *device = tty->disc_data;
    size_t index;

    if (!device || READ_ONCE(device->disconnected))
        return;
    for (index = 0; flags && index < length; index++)
        if (flags[index]) {
            atomic_cmpxchg(&device->io_error, 0, -EIO);
            queue_work(device->workqueue, &device->rx_work);
            return;
        }
    melodi_usb_receive(device, data, length);
}

static void melodi_tty_write_wakeup(struct tty_struct *tty)
{
    wake_up_interruptible(&tty->write_wait);
}

static void melodi_tty_hangup(struct tty_struct *tty)
{
    melodi_tty_close(tty);
    schedule_work(&melodi_tty_reap_work);
}

static struct tty_ldisc_ops melodi_tty_ldisc = {
    .owner = THIS_MODULE,
    .num = N_DEVELOPMENT,
    .name = "n_melodi",
    .open = melodi_tty_open,
    .close = melodi_tty_close,
    .hangup = melodi_tty_hangup,
    .receive_buf = melodi_tty_receive_buf,
    .write_wakeup = melodi_tty_write_wakeup,
};

static int melodi_tty_parse_device(const char *value, dev_t *device)
{
    char text[32];
    char *separator;
    unsigned int major;
    unsigned int minor;
    int error;

    if (strscpy(text, value, sizeof(text)) < 0)
        return -E2BIG;
    strim(text);
    separator = strchr(text, ':');
    if (!separator || separator == text || !separator[1])
        return -EINVAL;
    *separator++ = '\0';
    error = kstrtouint(text, 10, &major);
    if (!error)
        error = kstrtouint(separator, 10, &minor);
    if (error)
        return error;
    *device = MKDEV(major, minor);
    if (MAJOR(*device) != major || MINOR(*device) != minor)
        return -EINVAL;
    return 0;
}

static void melodi_tty_configure(struct tty_struct *tty)
{
    down_write(&tty->termios_rwsem);
    tty->termios.c_iflag = 0;
    tty->termios.c_oflag = 0;
    tty->termios.c_lflag = 0;
    tty->termios.c_cflag &= ~(CSIZE | PARENB | CSTOPB | CRTSCTS);
    tty->termios.c_cflag |= CS8 | CREAD | CLOCAL;
    tty_encode_baud_rate(tty, 115200, 115200);
    up_write(&tty->termios_rwsem);
}

static int melodi_tty_attach_device(dev_t number)
{
    struct tty_struct *tty;
    unsigned int index;
    int error = -ENOSPC;

    mutex_lock(&melodi_tty_lock);
    if (!melodi_tty_ready) {
        error = -EAGAIN;
        goto unlock;
    }
    for (index = 0; index < MELODI_TTY_LIMIT; index++) {
        if (melodi_ttys[index] && tty_devnum(melodi_ttys[index]) == number) {
            error = 0;
            goto unlock;
        }
        if (!melodi_ttys[index] && error == -ENOSPC)
            error = index;
    }
    if (error < 0)
        goto unlock;
    index = error;
    tty = tty_kopen_exclusive(number);
    if (IS_ERR(tty)) {
        error = PTR_ERR(tty);
        goto unlock;
    }
    melodi_tty_configure(tty);
    error = tty->ops->open ? tty->ops->open(tty, NULL) : -ENODEV;
    if (error && tty->ops->close)
        tty->ops->close(tty, NULL);
    if (!error)
        clear_bit(TTY_HUPPED, &tty->flags);
    tty_unlock(tty);
    if (error) {
        tty_kclose(tty);
        goto unlock;
    }
    error = tty_set_ldisc(tty, N_DEVELOPMENT);
    if (error) {
        tty_lock(tty);
        if (tty->ops->close)
            tty->ops->close(tty, NULL);
        tty_unlock(tty);
        tty_kclose(tty);
        goto unlock;
    }
    melodi_ttys[index] = tty;
unlock:
    mutex_unlock(&melodi_tty_lock);
    return error;
}

static int melodi_tty_release_device(dev_t number)
{
    struct tty_struct *tty = NULL;
    unsigned int index;
    int error = -ENOENT;

    mutex_lock(&melodi_tty_lock);
    for (index = 0; index < MELODI_TTY_LIMIT; index++) {
        if (!melodi_ttys[index] || tty_devnum(melodi_ttys[index]) != number)
            continue;
        tty = melodi_ttys[index];
        error = tty_set_ldisc(tty, N_TTY);
        if (!error)
            melodi_ttys[index] = NULL;
        break;
    }
    mutex_unlock(&melodi_tty_lock);
    if (!error) {
        tty_lock(tty);
        if (!test_bit(TTY_HUPPED, &tty->flags) && tty->ops->close)
            tty->ops->close(tty, NULL);
        tty_unlock(tty);
        tty_kclose(tty);
    }
    return error;
}

static void melodi_tty_reap(struct work_struct *work)
{
    struct tty_struct *tty;
    unsigned int index;

    (void)work;
    for (index = 0; index < MELODI_TTY_LIMIT; index++) {
        mutex_lock(&melodi_tty_lock);
        tty = melodi_ttys[index];
        if (tty)
            tty_lock(tty);
        if (!tty || !test_bit(TTY_HUPPED, &tty->flags)) {
            if (tty)
                tty_unlock(tty);
            mutex_unlock(&melodi_tty_lock);
            continue;
        }
        melodi_ttys[index] = NULL;
        tty_unlock(tty);
        mutex_unlock(&melodi_tty_lock);
        tty_kclose(tty);
    }
}

static void melodi_tty_release_all(void)
{
    struct tty_struct *ttys[MELODI_TTY_LIMIT] = { 0 };
    unsigned int index;

    mutex_lock(&melodi_tty_lock);
    melodi_tty_ready = false;
    for (index = 0; index < MELODI_TTY_LIMIT; index++) {
        ttys[index] = melodi_ttys[index];
        melodi_ttys[index] = NULL;
    }
    mutex_unlock(&melodi_tty_lock);
    for (index = 0; index < MELODI_TTY_LIMIT; index++) {
        if (!ttys[index])
            continue;
        tty_set_ldisc(ttys[index], N_TTY);
        tty_lock(ttys[index]);
        if (!test_bit(TTY_HUPPED, &ttys[index]->flags) &&
            ttys[index]->ops->close)
            ttys[index]->ops->close(ttys[index], NULL);
        tty_unlock(ttys[index]);
        tty_kclose(ttys[index]);
    }
}

static int melodi_tty_attach_set(const char *value,
                                 const struct kernel_param *parameter)
{
    dev_t number;
    int error;

    (void)parameter;
    error = melodi_tty_parse_device(value, &number);
    return error ? error : melodi_tty_attach_device(number);
}

static int melodi_tty_release_set(const char *value,
                                  const struct kernel_param *parameter)
{
    dev_t number;
    int error;

    (void)parameter;
    error = melodi_tty_parse_device(value, &number);
    return error ? error : melodi_tty_release_device(number);
}

static const struct kernel_param_ops melodi_tty_attach_ops = {
    .set = melodi_tty_attach_set,
};

static const struct kernel_param_ops melodi_tty_release_ops = {
    .set = melodi_tty_release_set,
};

module_param_cb(attach, &melodi_tty_attach_ops, NULL, 0200);
module_param_cb(release, &melodi_tty_release_ops, NULL, 0200);

static const struct usb_device_id melodi_usb_ids[] = {
    {
        .match_flags = USB_DEVICE_ID_MATCH_DEVICE |
                       USB_DEVICE_ID_MATCH_DEV_LO |
                       USB_DEVICE_ID_MATCH_DEV_HI |
                       USB_DEVICE_ID_MATCH_INT_INFO |
                       USB_DEVICE_ID_MATCH_INT_NUMBER,
        .idVendor = MELODI_USB_TEST_VENDOR,
        .idProduct = MELODI_USB_TEST_PRODUCT,
        .bcdDevice_lo = 0x0100,
        .bcdDevice_hi = 0x0100,
        .bInterfaceClass = MELODI_USB_TEST_CLASS,
        .bInterfaceSubClass = MELODI_USB_TEST_SUBCLASS,
        .bInterfaceProtocol = MELODI_USB_TEST_PROTOCOL,
        .bInterfaceNumber = MELODI_USB_TEST_INTERFACE,
        .driver_info = MELODI_USB_TEST_ID,
    },
    { }
};
MODULE_DEVICE_TABLE(usb, melodi_usb_ids);

static struct usb_driver melodi_usb_driver = {
    .name = "melodi_usb",
    .id_table = melodi_usb_ids,
    .probe = melodi_usb_probe,
    .disconnect = melodi_usb_disconnect,
    .suspend = melodi_usb_suspend,
    .resume = melodi_usb_resume,
    .reset_resume = melodi_usb_resume,
    .pre_reset = melodi_usb_pre_reset,
    .post_reset = melodi_usb_post_reset,
    .shutdown = melodi_usb_shutdown,
    .supports_autosuspend = 1,
    .no_dynamic_id = 1,
};

static int __init melodi_usb_init(void)
{
    int error;

    if (melodi_core_abi_version() != MELODI_CORE_ABI_VERSION)
        return -EPROTONOSUPPORT;
    INIT_WORK(&melodi_tty_reap_work, melodi_tty_reap);
    error = tty_register_ldisc(&melodi_tty_ldisc);
    if (error)
        return error;
    error = usb_register(&melodi_usb_driver);
    if (error) {
        tty_unregister_ldisc(&melodi_tty_ldisc);
        return error;
    }
    mutex_lock(&melodi_tty_lock);
    melodi_tty_ready = true;
    mutex_unlock(&melodi_tty_lock);
    return 0;
}

static void __exit melodi_usb_exit(void)
{
    cancel_work_sync(&melodi_tty_reap_work);
    melodi_tty_release_all();
    usb_deregister(&melodi_usb_driver);
    tty_unregister_ldisc(&melodi_tty_ldisc);
}

module_init(melodi_usb_init);
module_exit(melodi_usb_exit);

MODULE_AUTHOR("Melodi contributors");
MODULE_DESCRIPTION("Melodi USB radio transport");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1.0");
MODULE_ALIAS_LDISC(N_DEVELOPMENT);
