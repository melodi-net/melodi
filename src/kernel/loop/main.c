/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/workqueue.h>

#include <melodi/core.h>

struct melodi_loop_frame {
    struct list_head node;
    struct melodi_tx_meta metadata;
    struct sk_buff *frame;
    unsigned long due;
    u8 copies;
    bool locator_mismatch;
};

struct melodi_loop_endpoint {
    struct net_device *dev;
    struct net_device *peer;
    struct list_head pending;
    struct delayed_work work;
    spinlock_t lock;
    u32 link_locator;
    u16 queued;
    u8 index;
    bool configured;
    bool stopping;
};

static struct net_device *melodi_loop_devices[2];
static atomic64_t melodi_loop_sequences[2];
static unsigned int frame_mtu = MELODI_FRAME_MTU_MAX;
static unsigned int queue_limit = 128;
static unsigned int latency_ms;
static unsigned int reorder_hold_ms = 20;
static unsigned int drop_every;
static unsigned int duplicate_every;
static unsigned int corrupt_every;
static unsigned int reorder_every;
static unsigned int locator_mismatch_every;
static bool fault_reset;
static bool disconnected;

module_param(frame_mtu, uint, 0644);
module_param(queue_limit, uint, 0644);
module_param(latency_ms, uint, 0644);
module_param(reorder_hold_ms, uint, 0644);
module_param(drop_every, uint, 0644);
module_param(duplicate_every, uint, 0644);
module_param(corrupt_every, uint, 0644);
module_param(reorder_every, uint, 0644);
module_param(locator_mismatch_every, uint, 0644);
module_param(fault_reset, bool, 0644);

static void melodi_loop_purge(struct melodi_loop_endpoint *endpoint,
                              int error)
{
    struct melodi_loop_frame *item;
    struct melodi_loop_frame *next;
    LIST_HEAD(pending);
    unsigned long flags;

    cancel_delayed_work_sync(&endpoint->work);
    spin_lock_irqsave(&endpoint->lock, flags);
    list_splice_init(&endpoint->pending, &pending);
    endpoint->queued = 0;
    spin_unlock_irqrestore(&endpoint->lock, flags);
    list_for_each_entry_safe(item, next, &pending, node) {
        melodi_tx_complete(endpoint->dev, item->metadata.cookie, error);
        kfree_skb(item->frame);
        kfree(item);
    }
}

static int melodi_loop_disconnected_set(const char *value,
                                        const struct kernel_param *parameter)
{
    unsigned int index;
    int error;

    error = param_set_bool(value, parameter);
    if (error)
        return error;
    for (index = 0; index < ARRAY_SIZE(melodi_loop_devices); index++) {
        struct melodi_loop_endpoint *endpoint;

        if (!melodi_loop_devices[index])
            continue;
        endpoint = melodi_transport_priv(melodi_loop_devices[index]);
        if (READ_ONCE(disconnected)) {
            melodi_link_ready(melodi_loop_devices[index], false, 0);
            melodi_loop_purge(endpoint, -ENETDOWN);
        } else if (READ_ONCE(endpoint->configured)) {
            melodi_link_ready(melodi_loop_devices[index], true,
                              endpoint->link_locator);
        }
    }
    return 0;
}

static const struct kernel_param_ops melodi_loop_disconnected_ops = {
    .set = melodi_loop_disconnected_set,
    .get = param_get_bool,
};

module_param_cb(disconnected, &melodi_loop_disconnected_ops,
                &disconnected, 0644);

static struct melodi_loop_frame *melodi_loop_take(
    struct melodi_loop_endpoint *endpoint, unsigned long *delay)
{
    struct melodi_loop_frame *item;
    struct melodi_loop_frame *selected = NULL;
    unsigned long earliest = 0;
    unsigned long flags;

    *delay = 0;
    spin_lock_irqsave(&endpoint->lock, flags);
    if (endpoint->stopping) {
        spin_unlock_irqrestore(&endpoint->lock, flags);
        return NULL;
    }
    list_for_each_entry(item, &endpoint->pending, node)
        if (!selected || time_before(item->due, earliest)) {
            selected = item;
            earliest = item->due;
        }
    if (!selected) {
        spin_unlock_irqrestore(&endpoint->lock, flags);
        return NULL;
    }
    if (time_after(earliest, jiffies)) {
        *delay = earliest - jiffies;
        spin_unlock_irqrestore(&endpoint->lock, flags);
        return NULL;
    }
    list_del(&selected->node);
    endpoint->queued--;
    spin_unlock_irqrestore(&endpoint->lock, flags);
    return selected;
}

static void melodi_loop_work(struct work_struct *work)
{
    struct melodi_loop_endpoint *endpoint = container_of(
        to_delayed_work(work), struct melodi_loop_endpoint, work);
    struct melodi_loop_frame *item;
    unsigned long delay;

    for (;;) {
        struct melodi_rx_meta receive;
        unsigned int copy;

        item = melodi_loop_take(endpoint, &delay);
        if (!item) {
            if (delay)
                mod_delayed_work(system_wq, &endpoint->work, delay);
            return;
        }
        if (READ_ONCE(disconnected)) {
            melodi_tx_complete(endpoint->dev, item->metadata.cookie,
                               -ENETDOWN);
            kfree_skb(item->frame);
            kfree(item);
            continue;
        }
        memset(&receive, 0, sizeof(receive));
        receive.timestamp_ns = ktime_get_ns();
        receive.source_locator = item->metadata.source_locator;
        receive.destination_locator = item->metadata.destination_locator;
        if (item->locator_mismatch)
            receive.source_locator ^= 1;
        for (copy = 0; copy < item->copies; copy++) {
            receive.duplicates = copy;
            melodi_rx_frame(endpoint->peer, item->frame->data,
                            item->frame->len, &receive);
        }
        melodi_tx_complete(endpoint->dev, item->metadata.cookie, 0);
        kfree_skb(item->frame);
        kfree(item);
    }
}

static int melodi_loop_xmit(struct net_device *dev, struct sk_buff *frame,
                            const struct melodi_tx_meta *meta)
{
    struct melodi_loop_endpoint *endpoint = melodi_transport_priv(dev);
    struct melodi_loop_endpoint *peer;
    struct melodi_loop_frame *item;
    unsigned long flags;
    unsigned long due;
    u64 sequence;
    unsigned int corrupt_interval;
    unsigned int drop_interval;
    unsigned int duplicate_interval;
    unsigned int locator_mismatch_interval;
    unsigned int reorder_interval;
    bool corrupt;

    if (!endpoint || !endpoint->peer)
        return -ENETDOWN;
    peer = melodi_transport_priv(endpoint->peer);
    if (!peer || !READ_ONCE(endpoint->configured) ||
        READ_ONCE(endpoint->stopping) || READ_ONCE(disconnected) ||
        meta->source_locator != READ_ONCE(endpoint->link_locator) ||
        (meta->destination_locator != MELODI_LINK_LOCATOR_BROADCAST &&
         meta->destination_locator != READ_ONCE(peer->link_locator)))
        return -ENETDOWN;
    if (frame->len > READ_ONCE(frame_mtu))
        return -EMSGSIZE;
    if (xchg(&fault_reset, false)) {
        atomic64_set(&melodi_loop_sequences[0], 0);
        atomic64_set(&melodi_loop_sequences[1], 0);
    }
    sequence = atomic64_inc_return(&melodi_loop_sequences[endpoint->index]);
    drop_interval = READ_ONCE(drop_every);
    duplicate_interval = READ_ONCE(duplicate_every);
    corrupt_interval = READ_ONCE(corrupt_every);
    reorder_interval = READ_ONCE(reorder_every);
    locator_mismatch_interval = READ_ONCE(locator_mismatch_every);
    if (drop_interval && sequence % drop_interval == 0) {
        melodi_tx_complete(dev, meta->cookie, 0);
        kfree_skb(frame);
        return 0;
    }
    item = kzalloc(sizeof(*item), GFP_ATOMIC);
    if (!item)
        return -ENOMEM;
    corrupt = corrupt_interval && sequence % corrupt_interval == 0;
    if (corrupt && skb_cow(frame, 0)) {
        kfree(item);
        return -ENOMEM;
    }
    due = jiffies + msecs_to_jiffies(min_t(unsigned int,
                                           READ_ONCE(latency_ms), 60000));
    if (reorder_interval && sequence % reorder_interval == 0)
        due += msecs_to_jiffies(min_t(unsigned int,
                                      READ_ONCE(reorder_hold_ms), 60000));
    item->metadata = *meta;
    item->frame = frame;
    item->due = due;
    item->copies = duplicate_interval &&
                   sequence % duplicate_interval == 0 ? 2 : 1;
    item->locator_mismatch = locator_mismatch_interval &&
                             sequence % locator_mismatch_interval == 0;
    spin_lock_irqsave(&endpoint->lock, flags);
    if (endpoint->stopping || READ_ONCE(disconnected)) {
        spin_unlock_irqrestore(&endpoint->lock, flags);
        kfree(item);
        return -ENETDOWN;
    }
    if (endpoint->queued >= min_t(unsigned int,
                                  READ_ONCE(queue_limit), U16_MAX)) {
        spin_unlock_irqrestore(&endpoint->lock, flags);
        kfree(item);
        return -ENOBUFS;
    }
    if (corrupt)
        item->frame->data[0] ^= 0x80;
    list_add_tail(&item->node, &endpoint->pending);
    endpoint->queued++;
    spin_unlock_irqrestore(&endpoint->lock, flags);
    mod_delayed_work(system_wq, &endpoint->work, 0);
    return 0;
}

static int melodi_loop_configure(
    struct net_device *dev, const struct melodi_link_config *config,
    struct netlink_ext_ack *extack)
{
    struct melodi_loop_endpoint *endpoint = melodi_transport_priv(dev);

    (void)extack;
    if (!endpoint || !config)
        return -EINVAL;
    WRITE_ONCE(endpoint->configured, true);
    melodi_link_ready(dev, !READ_ONCE(disconnected),
                      endpoint->link_locator);
    return 0;
}

static void melodi_loop_get_info(struct net_device *dev,
                                 struct melodi_link_info *info)
{
    (void)dev;
    info->abi_version = MELODI_CORE_ABI_VERSION;
    info->frame_mtu = min_t(unsigned int, READ_ONCE(frame_mtu),
                            MELODI_FRAME_MTU_MAX);
    info->state = READ_ONCE(disconnected) ? MELODI_LINK_DISCONNECTED :
                  MELODI_LINK_READY;
    strscpy(info->driver_version, "loop-0.1.0",
            sizeof(info->driver_version));
    strscpy(info->firmware_version, "virtual",
            sizeof(info->firmware_version));
    strscpy(info->bus_info, "melodi-loop", sizeof(info->bus_info));
}

static const struct melodi_link_ops melodi_loop_ops = {
    .xmit = melodi_loop_xmit,
    .configure = melodi_loop_configure,
    .get_info = melodi_loop_get_info,
};

static void melodi_loop_endpoint_init(struct melodi_loop_endpoint *endpoint,
                                      struct net_device *dev, u8 index)
{
    endpoint->dev = dev;
    endpoint->index = index;
    endpoint->link_locator = 0x4d4c0001U + index;
    spin_lock_init(&endpoint->lock);
    INIT_LIST_HEAD(&endpoint->pending);
    INIT_DELAYED_WORK(&endpoint->work, melodi_loop_work);
}

static void melodi_loop_endpoint_stop(struct melodi_loop_endpoint *endpoint)
{
    unsigned long flags;

    spin_lock_irqsave(&endpoint->lock, flags);
    endpoint->stopping = true;
    spin_unlock_irqrestore(&endpoint->lock, flags);
    melodi_loop_purge(endpoint, -ENODEV);
}

static int __init melodi_loop_init(void)
{
    struct melodi_loop_endpoint *left;
    struct melodi_loop_endpoint *right;
    int error;

    if (melodi_core_abi_version() != MELODI_CORE_ABI_VERSION)
        return -EPROTONOSUPPORT;
    melodi_loop_devices[0] = melodi_attach_transport(NULL, sizeof(*left),
                                                     &melodi_loop_ops,
                                                     THIS_MODULE);
    if (IS_ERR(melodi_loop_devices[0]))
        return PTR_ERR(melodi_loop_devices[0]);
    melodi_loop_devices[1] = melodi_attach_transport(NULL, sizeof(*right),
                                                     &melodi_loop_ops,
                                                     THIS_MODULE);
    if (IS_ERR(melodi_loop_devices[1])) {
        melodi_detach_transport(melodi_loop_devices[0]);
        return PTR_ERR(melodi_loop_devices[1]);
    }
    left = melodi_transport_priv(melodi_loop_devices[0]);
    right = melodi_transport_priv(melodi_loop_devices[1]);
    melodi_loop_endpoint_init(left, melodi_loop_devices[0], 0);
    melodi_loop_endpoint_init(right, melodi_loop_devices[1], 1);
    left->peer = melodi_loop_devices[1];
    right->peer = melodi_loop_devices[0];
    error = melodi_transport_configure(melodi_loop_devices[0]);
    if (error && error != -EAGAIN)
        goto configure_error;
    error = melodi_transport_configure(melodi_loop_devices[1]);
    if (error && error != -EAGAIN)
        goto configure_error;
    return 0;

configure_error:
    melodi_loop_endpoint_stop(right);
    melodi_loop_endpoint_stop(left);
    melodi_detach_transport(melodi_loop_devices[1]);
    melodi_detach_transport(melodi_loop_devices[0]);
    return error;
}

static void __exit melodi_loop_exit(void)
{
    struct melodi_loop_endpoint *left =
        melodi_transport_priv(melodi_loop_devices[0]);
    struct melodi_loop_endpoint *right =
        melodi_transport_priv(melodi_loop_devices[1]);

    melodi_link_ready(melodi_loop_devices[0], false, 0);
    melodi_link_ready(melodi_loop_devices[1], false, 0);
    melodi_loop_endpoint_stop(right);
    melodi_loop_endpoint_stop(left);
    melodi_detach_transport(melodi_loop_devices[1]);
    melodi_detach_transport(melodi_loop_devices[0]);
}

module_init(melodi_loop_init);
module_exit(melodi_loop_exit);

MODULE_AUTHOR("Melodi contributors");
MODULE_DESCRIPTION("Melodi in-kernel virtual radio");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1.0");
