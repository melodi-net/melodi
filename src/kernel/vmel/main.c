/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include <melodi/core.h>

#define VMEL_FRAME_MTU 232
#define VMEL_FRAME_LIMIT MELODI_FRAME_MTU_MAX
#define VMEL_PACKET_US 100000

static unsigned int frame_mtu = VMEL_FRAME_MTU;
static unsigned int drop_every;
static unsigned int duplicate_every;
static unsigned int corrupt_every;
static unsigned int latency_ms;
static unsigned int duty_permille = 1000;
module_param(frame_mtu, uint, 0644);
module_param(drop_every, uint, 0644);
module_param(duplicate_every, uint, 0644);
module_param(corrupt_every, uint, 0644);
module_param(latency_ms, uint, 0644);
module_param(duty_permille, uint, 0644);

struct vmel_port {
    struct list_head node;
    struct net_device *dev;
    u32 locator;
    bool ready;
};

struct vmel_priv {
    struct vmel_port port;
};

static LIST_HEAD(vmel_ports);
static DEFINE_MUTEX(vmel_lock);
static atomic_t vmel_sequence = ATOMIC_INIT(0);

static struct vmel_port *vmel_port_of(struct net_device *dev)
{
    struct vmel_priv *priv = melodi_transport_priv(dev);

    return priv ? &priv->port : NULL;
}

static bool vmel_fault(unsigned int every)
{
    unsigned int count;

    if (!every)
        return false;
    count = (unsigned int)atomic_inc_return(&vmel_sequence);
    return count % every == 0;
}

static void vmel_deliver(struct vmel_port *source, struct sk_buff *frame,
                         const struct melodi_tx_meta *meta)
{
    struct melodi_rx_meta rx = {};
    struct vmel_port *port;
    u8 *copy;

    rx.timestamp_ns = ktime_get_ns();
    rx.source_locator = meta->source_locator;
    rx.destination_locator = meta->destination_locator;
    rx.rssi = -60;
    rx.snr = 10;
    list_for_each_entry(port, &vmel_ports, node) {
        if (port == source || !port->ready)
            continue;
        if (meta->destination_locator != MELODI_LINK_LOCATOR_BROADCAST &&
            meta->destination_locator != port->locator)
            continue;
        copy = kmemdup(frame->data, frame->len, GFP_KERNEL);
        if (!copy)
            continue;
        if (vmel_fault(corrupt_every) && frame->len)
            copy[frame->len / 2] ^= 0xff;
        melodi_rx_frame(port->dev, copy, frame->len, &rx);
        if (vmel_fault(duplicate_every))
            melodi_rx_frame(port->dev, copy, frame->len, &rx);
        kfree(copy);
    }
}

static int vmel_xmit(struct net_device *dev, struct sk_buff *frame,
                     const struct melodi_tx_meta *meta)
{
    struct vmel_port *source = vmel_port_of(dev);

    if (!source || !frame || !meta)
        return -EINVAL;
    if (frame->len > VMEL_FRAME_LIMIT)
        return -EMSGSIZE;
    if (latency_ms)
        msleep(latency_ms);
    if (!vmel_fault(drop_every)) {
        mutex_lock(&vmel_lock);
        vmel_deliver(source, frame, meta);
        mutex_unlock(&vmel_lock);
    }
    dev_consume_skb_any(frame);
    return 0;
}

static int vmel_configure(struct net_device *dev,
                          const struct melodi_link_config *config,
                          struct netlink_ext_ack *extack)
{
    struct vmel_port *port = vmel_port_of(dev);

    (void)extack;
    if (!port || !config)
        return -EINVAL;
    if (!config->locator ||
        config->locator == MELODI_LINK_LOCATOR_BROADCAST)
        return -EINVAL;
    mutex_lock(&vmel_lock);
    port->locator = config->locator;
    port->ready = true;
    mutex_unlock(&vmel_lock);
    melodi_link_ready(dev, true, config->locator);
    return 0;
}

static void vmel_get_info(struct net_device *dev,
                          struct melodi_link_info *info)
{
    (void)dev;
    info->abi_version = MELODI_CORE_ABI_VERSION;
    info->frame_mtu = frame_mtu;
    strscpy(info->driver_version, "vmel-0.1.0",
            sizeof(info->driver_version));
    strscpy(info->firmware_version, "virtual",
            sizeof(info->firmware_version));
    strscpy(info->bus_info, "melodi-vmel", sizeof(info->bus_info));
}

static int vmel_airtime(struct net_device *dev, const struct sk_buff *frame,
                        const struct melodi_tx_meta *meta,
                        struct melodi_airtime_charge *charge)
{
    (void)dev;
    (void)meta;
    if (!frame || !charge || !duty_permille || duty_permille > 1000)
        return -EINVAL;
    charge->duration_us = VMEL_PACKET_US;
    charge->budget_us = MELODI_AIRTIME_WINDOW_US * duty_permille / 1000;
    charge->broadcast_budget_us = charge->budget_us / 10;
    return 0;
}

static const struct melodi_link_ops vmel_link_ops = {
    .xmit = vmel_xmit,
    .configure = vmel_configure,
    .get_info = vmel_get_info,
    .airtime = vmel_airtime,
};

static void vmel_setup(struct net_device *dev)
{
    melodi_link_setup(dev);
}

static int vmel_newlink(struct net_device *dev,
                        struct rtnl_newlink_params *params,
                        struct netlink_ext_ack *extack)
{
    struct vmel_port *port;
    int error;

    (void)params;
    (void)extack;
    error = register_netdevice(dev);
    if (error)
        return error;
    error = melodi_link_attach(dev, &vmel_link_ops, THIS_MODULE,
                               sizeof(struct vmel_priv));
    if (error) {
        unregister_netdevice(dev);
        return error;
    }
    port = vmel_port_of(dev);
    port->dev = dev;
    mutex_lock(&vmel_lock);
    list_add_tail(&port->node, &vmel_ports);
    mutex_unlock(&vmel_lock);
    return 0;
}

static void vmel_dellink(struct net_device *dev, struct list_head *head)
{
    struct vmel_port *port = vmel_port_of(dev);

    if (port) {
        mutex_lock(&vmel_lock);
        port->ready = false;
        list_del(&port->node);
        mutex_unlock(&vmel_lock);
    }
    melodi_link_release(dev);
    unregister_netdevice_queue(dev, head);
}

static struct rtnl_link_ops vmel_rtnl_ops __read_mostly = {
    .kind = "vmel",
    .setup = vmel_setup,
    .newlink = vmel_newlink,
    .dellink = vmel_dellink,
};

static int __init vmel_init(void)
{
    vmel_rtnl_ops.priv_size = melodi_link_priv_size();
    return rtnl_link_register(&vmel_rtnl_ops);
}

static void __exit vmel_exit(void)
{
    rtnl_link_unregister(&vmel_rtnl_ops);
}

module_init(vmel_init);
module_exit(vmel_exit);

MODULE_AUTHOR("Melodi contributors");
MODULE_DESCRIPTION("Melodi virtual radio interfaces");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1.0");
MODULE_ALIAS_RTNL_LINK("vmel");
