/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MELODI_CORE_H
#define MELODI_CORE_H

#include <linux/device.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/types.h>

#include "melodi.h"

#define MELODI_CORE_ABI_VERSION 9
#define MELODI_LINK_LOCATOR_BROADCAST 0xffffffffU
#ifndef MELODI_AIRTIME_WINDOW_US
#define MELODI_AIRTIME_WINDOW_US 3600000000ULL
#endif

struct melodi_tx_meta {
    u32 destination_locator;
    u32 source_locator;
    u64 cookie;
};

struct melodi_rx_meta {
    u64 timestamp_ns;
    u32 source_locator;
    u32 destination_locator;
    u16 duplicates;
    s16 rssi;
    s16 snr;
    u8 hops;
    u8 retransmissions;
    bool authenticated;
};

struct melodi_link_config {
    u8 mesh_domain[32];
    u32 locator;
};

struct melodi_link_info {
    u32 abi_version;
    u32 frame_mtu;
    enum melodi_link_state state;
    char driver_version[MELODI_BUS_INFO_MAX + 1];
    char firmware_version[MELODI_BUS_INFO_MAX + 1];
    char bus_info[MELODI_BUS_INFO_MAX + 1];
};

struct melodi_airtime_charge {
    u64 duration_us;
    u64 budget_us;
    u64 broadcast_budget_us;
};

/**
 * struct melodi_link_ops - sleepable transport operations
 * @xmit: consumes the skb on zero; leaves ownership with the core on error
 * @configure: starts a complete readiness configuration for the supplied link
 * @get_info: fills bounded display and frame-MTU fields
 * @airtime: fills conservative duration and one-hour budgets in microseconds
 *
 * Operations run in process context. A backend stops its callbacks and device
 * work before melodi_detach_transport(). Detach waits for active core calls.
 * Attachment returns a borrowed registered netdevice valid through detach.
 */
struct melodi_link_ops {
    int (*xmit)(struct net_device *dev, struct sk_buff *frame,
                const struct melodi_tx_meta *meta);
    int (*configure)(struct net_device *dev,
                     const struct melodi_link_config *config,
                     struct netlink_ext_ack *extack);
    void (*get_info)(struct net_device *dev, struct melodi_link_info *info);
    int (*airtime)(struct net_device *dev, const struct sk_buff *frame,
                   const struct melodi_tx_meta *meta,
                   struct melodi_airtime_charge *charge);
};

size_t melodi_link_priv_size(void);
void melodi_link_setup(struct net_device *dev);
int melodi_link_attach(struct net_device *dev,
                       const struct melodi_link_ops *ops,
                       struct module *owner, size_t driver_private_size);
void melodi_link_release(struct net_device *dev);
struct net_device *melodi_attach_transport(struct device *parent,
                                           size_t driver_private_size,
                                           const struct melodi_link_ops *ops,
                                           struct module *owner);
struct net_device *melodi_attach_selected_transport(
    struct device *parent, const char *radio_serial,
    size_t driver_private_size, const struct melodi_link_ops *ops,
    struct module *owner);
void *melodi_transport_priv(struct net_device *dev);
int melodi_set_transport_selector(struct net_device *dev,
                                  const char *radio_serial);
int melodi_transport_configure(struct net_device *dev);
void melodi_detach_transport(struct net_device *dev);
int melodi_rx_frame(struct net_device *dev, const void *frame, size_t length,
                    const struct melodi_rx_meta *meta);
void melodi_tx_complete(struct net_device *dev, u64 cookie, int error);
void melodi_link_ready(struct net_device *dev, bool ready,
                       u32 local_locator);
void melodi_link_failed(struct net_device *dev,
                        enum melodi_link_failure failure, int error);
u32 melodi_core_abi_version(void);

#endif
