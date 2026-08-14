/* SPDX-License-Identifier: GPL-2.0-only */
#include "internal.h"

#include <linux/if_arp.h>
#include <linux/ethtool.h>
#include <linux/init.h>
#include <linux/key.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>

#include "wire.h"
#include "crypto/monocypher.h"

static LIST_HEAD(melodi_devices);
static DEFINE_MUTEX(melodi_devices_lock);
static unsigned int interface_count = 1;
static char *radio_serials[8];
static unsigned int radio_serial_count;
module_param_named(interfaces, interface_count, uint, 0444);
module_param_array_named(radios, radio_serials, charp, &radio_serial_count,
                         0444);

#define MELODI_CORE_VERSION "0.1.0"

static const char melodi_stat_names[][ETH_GSTRING_LEN] = {
    "rx_packets", "rx_bytes", "rx_errors", "rx_dropped",
    "tx_packets", "tx_bytes", "tx_errors", "tx_dropped",
    "tx_queue_frames", "tx_queue_bytes", "authenticated_peers",
    "reassemblies", "reliable_pending", "discovery_pending",
    "auth_failures",
    "replay_drops", "broadcast_tx", "broadcast_rx", "airtime_us",
    "broadcast_airtime_us", "duty_defers", "queue_expired",
    "app_delivery_drops", "monitor_drops",
};

static_assert(ARRAY_SIZE(melodi_stat_names) == MELODI_STAT_A_MAX);

bool melodi_node_id_valid(const struct melodi_node_id *node_id)
{
    static const u8 prime[MELODI_NODE_KEY_SIZE] = {
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    };
    u8 encoded[MELODI_NODE_KEY_SIZE];
    u8 different_zero = 0;
    u8 different_ones = 0;
    int index;

    if (!node_id || node_id->bytes[0] != MELODI_NODE_ID_SCHEME_ED25519)
        return false;
    memcpy(encoded, node_id->bytes + 1, sizeof(encoded));
    for (index = 0; index < MELODI_NODE_KEY_SIZE; index++) {
        different_zero |= encoded[index];
        different_ones |= encoded[index] ^ 0xffU;
    }
    if (!different_zero || !different_ones)
        return false;
    encoded[31] &= 0x7f;
    for (index = MELODI_NODE_KEY_SIZE - 1; index >= 0; index--) {
        if (encoded[index] < prime[index])
            return true;
        if (encoded[index] > prime[index])
            return false;
    }
    return crypto_eddsa_public_key_check(node_id->bytes + 1) == 0;
}

int melodi_counter_next_locked(struct melodi_device *melodi, u64 *counter)
{
    if (melodi->transmit_counter == U64_MAX)
        return -EOVERFLOW;
    *counter = ++melodi->transmit_counter;
    return 0;
}

struct melodi_device_entry {
    struct list_head node;
    struct net_device *dev;
};

static bool melodi_logical_skb_valid(const struct sk_buff *skb,
                                     struct melodi_logical_header *header)
{
    if (skb->protocol != 0 ||
        skb_headlen(skb) < sizeof(*header))
        return false;
    memcpy(header, skb->data, sizeof(*header));
    return header->magic == MELODI_LOGICAL_MAGIC &&
           header->version == MELODI_LOGICAL_VERSION &&
           header->header_length == sizeof(*header) &&
           header->reservation_id &&
           header->payload_length <= MELODI_MESSAGE_MTU &&
           skb->len == sizeof(*header) + header->payload_length;
}

static void melodi_logical_tx_work(struct work_struct *work)
{
    struct melodi_device *melodi = container_of(
        work, struct melodi_device, logical_tx_work);
    struct melodi_logical_header header;
    struct netdev_queue *txq;
    struct sk_buff *skb;
    const void *destination;
    const void *payload;
    unsigned int length;
    int error;

    while ((skb = skb_dequeue(&melodi->logical_tx_queue))) {
        length = skb->len;
        txq = netdev_get_tx_queue(melodi->netdev,
                                  skb_get_queue_mapping(skb));
        if (!melodi_logical_skb_valid(skb, &header)) {
            melodi->netdev->stats.tx_dropped++;
            goto complete;
        }
        error = melodi_queue_reservation_claim(
            melodi->netdev, header.reservation_id, skb->data, skb->len);
        if (error) {
            melodi->netdev->stats.tx_dropped++;
            goto complete;
        }
        destination = header.flags & MELODI_F_BROADCAST ?
                      NULL : &header.destination;
        payload = skb->data + sizeof(header);
        error = melodi_data_send_reserved(
            melodi->netdev, destination, header.source_service,
            header.destination_service, payload, header.payload_length,
            header.flags, header.cookie, header.ttl_ms,
            header.binding_portid, header.binding_generation,
            header.priority, header.reservation_id);
        melodi_queue_reservation_cancel(
            melodi->netdev, header.reservation_id, error, error != 0);
        if (error)
            melodi->netdev->stats.tx_dropped++;
complete:
        netdev_tx_completed_queue(txq, 1, length);
        dev_kfree_skb_any(skb);
    }
}

static void melodi_logical_start(struct melodi_device *melodi)
{
    WRITE_ONCE(melodi->logical_tx_stopping, false);
}

static void melodi_logical_stop(struct melodi_device *melodi, int error)
{
    struct melodi_logical_header header;
    struct netdev_queue *txq;
    struct sk_buff *skb;

    WRITE_ONCE(melodi->logical_tx_stopping, true);
    cancel_work_sync(&melodi->logical_tx_work);
    while ((skb = skb_dequeue(&melodi->logical_tx_queue))) {
        txq = netdev_get_tx_queue(melodi->netdev,
                                  skb_get_queue_mapping(skb));
        if (melodi_logical_skb_valid(skb, &header))
            melodi_queue_reservation_cancel(
                melodi->netdev, header.reservation_id, error, true);
        netdev_tx_completed_queue(txq, 1, skb->len);
        melodi->netdev->stats.tx_dropped++;
        dev_kfree_skb_any(skb);
    }
}

static netdev_tx_t melodi_start_xmit(struct sk_buff *skb,
                                     struct net_device *dev)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_logical_header header;
    struct netdev_queue *txq;
    unsigned long irq_flags;

    if (!melodi_logical_skb_valid(skb, &header) ||
        READ_ONCE(melodi->logical_tx_stopping))
        goto drop;
    spin_lock_irqsave(&melodi->logical_tx_queue.lock, irq_flags);
    if (melodi->logical_tx_queue.qlen >= MELODI_LOGICAL_QUEUE_LIMIT) {
        spin_unlock_irqrestore(&melodi->logical_tx_queue.lock, irq_flags);
        goto drop;
    }
    __skb_queue_tail(&melodi->logical_tx_queue, skb);
    spin_unlock_irqrestore(&melodi->logical_tx_queue.lock, irq_flags);
    txq = netdev_get_tx_queue(dev, skb_get_queue_mapping(skb));
    netdev_tx_sent_queue(txq, skb->len);
    schedule_work(&melodi->logical_tx_work);
    return NETDEV_TX_OK;
drop:
    dev_kfree_skb_any(skb);
    dev->stats.tx_dropped++;
    return NETDEV_TX_OK;
}

static int melodi_open(struct net_device *dev)
{
    struct melodi_device *melodi = netdev_priv(dev);

    melodi_logical_start(melodi);
    netif_tx_start_all_queues(dev);
    if (netif_carrier_ok(dev)) {
        melodi_queue_start(dev);
        melodi_discovery_announce(dev);
    }
    return 0;
}

static int melodi_stop(struct net_device *dev)
{
    struct melodi_device *melodi = netdev_priv(dev);
    bool connected = netif_carrier_ok(dev);

    netif_tx_stop_all_queues(dev);
    if (connected)
        melodi_netlink_link_error(dev, -ENETDOWN);
    melodi_logical_stop(melodi, -ENETDOWN);
    melodi_queue_pause(dev);
    melodi_data_fail_pending(dev, -ENETDOWN);
    return 0;
}

static const struct net_device_ops melodi_netdev_ops = {
    .ndo_open = melodi_open,
    .ndo_stop = melodi_stop,
    .ndo_start_xmit = melodi_start_xmit,
};

void melodi_stats_read(struct net_device *dev,
                       struct melodi_stats_snapshot *snapshot)
{
    struct melodi_device *melodi = netdev_priv(dev);
    unsigned int index;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->values[MELODI_STAT_A_RX_PACKETS] = READ_ONCE(dev->stats.rx_packets);
    snapshot->values[MELODI_STAT_A_RX_BYTES] = READ_ONCE(dev->stats.rx_bytes);
    snapshot->values[MELODI_STAT_A_RX_ERRORS] = READ_ONCE(dev->stats.rx_errors);
    snapshot->values[MELODI_STAT_A_RX_DROPPED] = READ_ONCE(dev->stats.rx_dropped);
    snapshot->values[MELODI_STAT_A_TX_PACKETS] = READ_ONCE(dev->stats.tx_packets);
    snapshot->values[MELODI_STAT_A_TX_BYTES] = READ_ONCE(dev->stats.tx_bytes);
    snapshot->values[MELODI_STAT_A_TX_ERRORS] = READ_ONCE(dev->stats.tx_errors);
    snapshot->values[MELODI_STAT_A_TX_DROPPED] = READ_ONCE(dev->stats.tx_dropped);
    melodi_queue_stats(
        dev, &snapshot->values[MELODI_STAT_A_TX_QUEUE_FRAMES],
        &snapshot->values[MELODI_STAT_A_TX_QUEUE_BYTES],
        &snapshot->values[MELODI_STAT_A_AIRTIME_US],
        &snapshot->values[MELODI_STAT_A_BROADCAST_AIRTIME_US]);
    mutex_lock(&melodi->lock);
    for (index = 0; index < MELODI_PEER_LIMIT; index++)
        snapshot->values[MELODI_STAT_A_AUTHENTICATED_PEERS] +=
            melodi->peers[index].session_ready;
    for (index = 0; index < MELODI_REASSEMBLY_LIMIT; index++)
        snapshot->values[MELODI_STAT_A_REASSEMBLIES] +=
            melodi->reassemblies[index].active;
    for (index = 0; index < MELODI_PENDING_LIMIT; index++)
        snapshot->values[MELODI_STAT_A_RELIABLE_PENDING] +=
            melodi->pending[index].allocated;
    snapshot->values[MELODI_STAT_A_DISCOVERY_PENDING] =
        melodi->discovery_count;
    mutex_unlock(&melodi->lock);
    snapshot->values[MELODI_STAT_A_AUTH_FAILURES] =
        atomic64_read(&melodi->auth_failures);
    snapshot->values[MELODI_STAT_A_REPLAY_DROPS] =
        atomic64_read(&melodi->replay_drops);
    snapshot->values[MELODI_STAT_A_BROADCAST_TX] =
        atomic64_read(&melodi->broadcast_tx);
    snapshot->values[MELODI_STAT_A_BROADCAST_RX] =
        atomic64_read(&melodi->broadcast_rx);
    snapshot->values[MELODI_STAT_A_DUTY_DEFERS] =
        atomic64_read(&melodi->duty_defers);
    snapshot->values[MELODI_STAT_A_QUEUE_EXPIRED] =
        atomic64_read(&melodi->queue_expired);
    snapshot->values[MELODI_STAT_A_APP_DELIVERY_DROPS] =
        atomic64_read(&melodi->app_delivery_drops);
    snapshot->values[MELODI_STAT_A_MONITOR_DROPS] =
        atomic64_read(&melodi->monitor_drops);
}

static void melodi_get_drvinfo(struct net_device *dev,
                               struct ethtool_drvinfo *info)
{
    struct melodi_link_info link = {};

    strscpy(info->driver, "melodi_core", sizeof(info->driver));
    strscpy(info->version, MELODI_CORE_VERSION, sizeof(info->version));
    if (melodi_core_link_info(dev, &link))
        return;
    if (link.driver_version[0])
        snprintf(info->version, sizeof(info->version), "%s/%.24s",
                 MELODI_CORE_VERSION, link.driver_version);
    if (link.firmware_version[0])
        strscpy(info->fw_version, link.firmware_version,
                sizeof(info->fw_version));
    if (link.bus_info[0])
        strscpy(info->bus_info, link.bus_info, sizeof(info->bus_info));
}

static int melodi_get_sset_count(struct net_device *dev, int set)
{
    (void)dev;
    return set == ETH_SS_STATS ? MELODI_STAT_A_MAX : -EOPNOTSUPP;
}

static void melodi_get_strings(struct net_device *dev, u32 set, u8 *data)
{
    (void)dev;
    if (set == ETH_SS_STATS)
        memcpy(data, melodi_stat_names, sizeof(melodi_stat_names));
}

static void melodi_get_ethtool_stats(struct net_device *dev,
                                     struct ethtool_stats *header, u64 *data)
{
    struct melodi_stats_snapshot snapshot;
    unsigned int index;

    (void)header;
    melodi_stats_read(dev, &snapshot);
    for (index = 1; index <= MELODI_STAT_A_MAX; index++)
        data[index - 1] = snapshot.values[index];
}

static const struct ethtool_ops melodi_ethtool_ops = {
    .get_drvinfo = melodi_get_drvinfo,
    .get_link = ethtool_op_get_link,
    .get_sset_count = melodi_get_sset_count,
    .get_strings = melodi_get_strings,
    .get_ethtool_stats = melodi_get_ethtool_stats,
};

static void melodi_setup(struct net_device *dev)
{
    dev->netdev_ops = &melodi_netdev_ops;
    dev->ethtool_ops = &melodi_ethtool_ops;
    dev->type = ARPHRD_NONE;
    dev->flags = IFF_NOARP | IFF_POINTOPOINT;
    dev->priv_flags |= IFF_NO_ADDRCONF;
    dev->addr_len = 0;
    dev->hard_header_len = 0;
    dev->mtu = MELODI_MESSAGE_MTU;
    dev->min_mtu = 1;
    dev->max_mtu = MELODI_MESSAGE_MTU;
    dev->tx_queue_len = 100;
    dev->needs_free_netdev = true;
}

static void melodi_device_init(struct net_device *dev, bool persistent)
{
    struct melodi_device *melodi = netdev_priv(dev);

    melodi->magic = MELODI_DEVICE_MAGIC;
    melodi->netdev = dev;
    mutex_init(&melodi->lock);
    get_random_bytes(&melodi->logical_key, sizeof(melodi->logical_key));
    skb_queue_head_init(&melodi->logical_tx_queue);
    INIT_WORK(&melodi->logical_tx_work, melodi_logical_tx_work);
    melodi->logical_tx_stopping = true;
    melodi_data_init(melodi);
    melodi_discovery_init(melodi);
    melodi_queue_init(melodi);
    melodi->broadcast_allowed = true;
    melodi->persistent = persistent;
    melodi->link_state = MELODI_LINK_DISCONNECTED;
    netif_carrier_off(dev);
}

size_t melodi_link_priv_size(void)
{
    return sizeof(struct melodi_device);
}
EXPORT_SYMBOL_GPL(melodi_link_priv_size);

void melodi_link_setup(struct net_device *dev)
{
    melodi_setup(dev);
    melodi_device_init(dev, false);
}
EXPORT_SYMBOL_GPL(melodi_link_setup);

static struct net_device *melodi_alloc_device(bool persistent)
{
    struct melodi_device_entry *entry;
    struct melodi_device *melodi;
    struct net_device *dev;
    int error;

    dev = alloc_netdev_mqs(sizeof(*melodi), "mel%d", NET_NAME_ENUM,
                           melodi_setup, 4, 1);
    if (!dev)
        return ERR_PTR(-ENOMEM);
    melodi = netdev_priv(dev);
    melodi_device_init(dev, persistent);
    error = register_netdev(dev);
    if (error) {
        free_netdev(dev);
        return ERR_PTR(error);
    }
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        unregister_netdev(dev);
        return ERR_PTR(-ENOMEM);
    }
    entry->dev = dev;
    mutex_lock(&melodi_devices_lock);
    list_add_tail(&entry->node, &melodi_devices);
    mutex_unlock(&melodi_devices_lock);
    return dev;
}

static void melodi_unregister_device(struct net_device *dev)
{
    struct melodi_device_entry *entry;
    struct melodi_device_entry *next;
    struct melodi_device *melodi = netdev_priv(dev);

    melodi_netlink_interface_removed(dev);
    mutex_lock(&melodi_devices_lock);
    list_for_each_entry_safe(entry, next, &melodi_devices, node) {
        if (entry->dev == dev) {
            list_del(&entry->node);
            kfree(entry);
            break;
        }
    }
    mutex_unlock(&melodi_devices_lock);
    melodi_logical_stop(melodi, -ENODEV);
    melodi_queue_stop(dev);
    melodi_discovery_stop(melodi);
    melodi_data_stop(melodi);
    if (melodi->identity_key)
        key_put(melodi->identity_key);
    unregister_netdev(dev);
}

struct net_device *melodi_device_get(struct net *net, int ifindex)
{
    struct melodi_device *melodi;
    struct net_device *dev;

    dev = dev_get_by_index(net, ifindex);
    if (!dev)
        return NULL;
    if (dev->netdev_ops != &melodi_netdev_ops) {
        dev_put(dev);
        return NULL;
    }
    melodi = netdev_priv(dev);
    if (melodi->magic != MELODI_DEVICE_MAGIC) {
        dev_put(dev);
        return NULL;
    }
    return dev;
}

bool melodi_device_is(const struct net_device *dev)
{
    const struct melodi_device *melodi;

    if (!dev || dev->netdev_ops != &melodi_netdev_ops)
        return false;
    melodi = netdev_priv(dev);
    return melodi->magic == MELODI_DEVICE_MAGIC;
}

bool melodi_device_identity(struct net_device *dev,
                            struct melodi_node_id *node_id,
                            u32 *generation)
{
    struct melodi_device *melodi = netdev_priv(dev);
    bool ready;

    mutex_lock(&melodi->lock);
    ready = melodi->identity_ready;
    if (ready && node_id)
        *node_id = melodi->node_id;
    if (ready && generation)
        *generation = melodi->identity_generation;
    mutex_unlock(&melodi->lock);
    return ready;
}

void melodi_namespace_reset(struct net_device *dev)
{
    struct melodi_device *melodi;
    bool restart;

    if (!melodi_device_is(dev))
        return;
    melodi = netdev_priv(dev);
    netif_tx_stop_all_queues(dev);
    melodi_logical_stop(melodi, -ENONET);
    melodi_queue_fail(dev, -ENONET);
    melodi_data_fail_pending(dev, -ENONET);
    mutex_lock(&melodi->lock);
    melodi_data_reset_locked(melodi);
    melodi_discovery_reset_locked(melodi);
    memzero_explicit(melodi->policy_peers,
                     sizeof(melodi->policy_peers));
    memzero_explicit(melodi->policy_services,
                     sizeof(melodi->policy_services));
    melodi->policy_mode = MELODI_POLICY_ALLOW_AUTHENTICATED;
    melodi->broadcast_allowed = true;
    restart = melodi->identity_ready && melodi->transport_ready &&
              netif_running(dev);
    mutex_unlock(&melodi->lock);
    if (restart) {
        melodi_queue_start(dev);
        melodi_logical_start(melodi);
        netif_tx_wake_all_queues(dev);
    }
}

int melodi_device_set_identity(struct net_device *dev,
                               const struct melodi_node_id *node_id,
                               struct key *identity_key, u32 generation,
                               const struct melodi_node_id *previous_node_id)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct key *previous;
    u32 collision_round;
    u32 native_locator;
    bool replacing;
    bool announce;
    bool configure;
    bool connected;
    int error;

    if (!melodi_node_id_valid(node_id) || !identity_key || !generation)
        return -EINVAL;
    mutex_lock(&melodi->lock);
    error = melodi_map_native_locator(
        melodi->mesh_domain, node_id, 0, &native_locator,
        &collision_round);
    replacing = melodi->identity_ready &&
                memcmp(&melodi->node_id, node_id, sizeof(*node_id));
    if (!error && melodi->identity_ready && !replacing &&
        generation <= melodi->identity_generation)
        error = -ESTALE;
    if (!error && previous_node_id &&
        (!replacing || memcmp(previous_node_id, &melodi->node_id,
                              sizeof(*previous_node_id))))
        error = -ESTALE;
    mutex_unlock(&melodi->lock);
    if (error)
        return error;
    connected = netif_carrier_ok(dev);
    netif_carrier_off(dev);
    netif_tx_stop_all_queues(dev);
    melodi_logical_stop(melodi, -EKEYREVOKED);
    melodi_queue_fail(dev, -EKEYREVOKED);
    melodi_data_fail_pending(dev, -EKEYREVOKED);
    if (connected)
        melodi_netlink_link_error(dev, -EKEYREVOKED);
    mutex_lock(&melodi->lock);
    previous = melodi->identity_key;
    melodi->identity_key = key_get(identity_key);
    melodi->node_id = *node_id;
    melodi->identity_ready = true;
    melodi->identity_generation = generation;
    melodi->local_native_locator = native_locator;
    melodi->local_collision_round = collision_round;
    melodi->conflict_pending = false;
    melodi->transmit_counter = 0;
    melodi_data_reset_locked(melodi);
    melodi_discovery_reset_locked(melodi);
    if (replacing && !previous_node_id)
        memset(melodi->policy_peers, 0, sizeof(melodi->policy_peers));
    configure = melodi->transport && melodi->transport->ops &&
                melodi->transport->ops->configure;
    if (configure) {
        melodi->transport_ready = false;
        melodi->local_link_locator = 0;
        melodi->link_state = MELODI_LINK_CONFIGURING;
        melodi->link_failure = MELODI_LINK_FAILURE_NONE;
        melodi->link_error = 0;
        netif_carrier_off(dev);
        netif_dormant_on(dev);
        netif_tx_stop_all_queues(dev);
    } else if (melodi->transport_ready) {
        melodi->link_state = MELODI_LINK_READY;
        melodi->link_failure = MELODI_LINK_FAILURE_NONE;
        melodi->link_error = 0;
        netif_dormant_off(dev);
        netif_carrier_on(dev);
        melodi_queue_start(dev);
        if (netif_running(dev)) {
            melodi_logical_start(melodi);
            netif_tx_wake_all_queues(dev);
        }
    }
    announce = melodi->transport_ready && netif_running(dev);
    mutex_unlock(&melodi->lock);
    if (previous)
        key_put(previous);
    if (configure)
        melodi_transport_configure(dev);
    if (announce)
        melodi_discovery_announce(dev);
    return 0;
}

int melodi_core_xmit(struct net_device *dev, struct sk_buff *skb,
                     const struct melodi_tx_meta *meta)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_transport *transport;
    int error;

    if (!netif_running(dev) || !netif_carrier_ok(dev))
        return -ENETDOWN;
    mutex_lock(&melodi->lock);
    transport = melodi->transport;
    if (!transport || !transport->ops || !transport->ops->xmit ||
        !refcount_inc_not_zero(&transport->references)) {
        mutex_unlock(&melodi->lock);
        return -ENETDOWN;
    }
    mutex_unlock(&melodi->lock);
    error = transport->ops->xmit(dev, skb, meta);
    if (refcount_dec_and_test(&transport->references))
        complete(&transport->released);
    return error;
}

int melodi_core_airtime(struct net_device *dev, const struct sk_buff *skb,
                        const struct melodi_tx_meta *meta,
                        struct melodi_airtime_charge *charge)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_transport *transport;
    int error = 0;

    if (!skb || !meta || !charge)
        return -EINVAL;
    memset(charge, 0, sizeof(*charge));
    mutex_lock(&melodi->lock);
    transport = melodi->transport;
    if (!transport || !transport->ops ||
        !refcount_inc_not_zero(&transport->references)) {
        mutex_unlock(&melodi->lock);
        return -ENETDOWN;
    }
    mutex_unlock(&melodi->lock);
    if (transport->ops->airtime)
        error = transport->ops->airtime(dev, skb, meta, charge);
    if (!error && transport->ops->airtime &&
        (!charge->duration_us || !charge->budget_us ||
         !charge->broadcast_budget_us ||
         charge->budget_us > MELODI_AIRTIME_WINDOW_US ||
         charge->broadcast_budget_us > charge->budget_us ||
         charge->duration_us > MELODI_AIRTIME_WINDOW_US))
        error = -EPROTO;
    if (refcount_dec_and_test(&transport->references))
        complete(&transport->released);
    return error;
}

int melodi_core_link_info(struct net_device *dev,
                          struct melodi_link_info *info)
{
    struct melodi_device *melodi;
    struct melodi_link_info link = {
        .abi_version = MELODI_CORE_ABI_VERSION,
        .frame_mtu = MELODI_FRAME_MTU_MAX,
    };
    struct melodi_transport *transport;

    if (!dev || !info)
        return -EINVAL;
    melodi = netdev_priv(dev);
    mutex_lock(&melodi->lock);
    transport = melodi->transport;
    if (!transport || !transport->ops ||
        !refcount_inc_not_zero(&transport->references)) {
        mutex_unlock(&melodi->lock);
        return -ENETDOWN;
    }
    mutex_unlock(&melodi->lock);
    if (transport->ops->get_info)
        transport->ops->get_info(dev, &link);
    if (refcount_dec_and_test(&transport->references))
        complete(&transport->released);
    link.driver_version[sizeof(link.driver_version) - 1] = 0;
    link.firmware_version[sizeof(link.firmware_version) - 1] = 0;
    link.bus_info[sizeof(link.bus_info) - 1] = 0;
    if (link.abi_version != MELODI_CORE_ABI_VERSION ||
        link.frame_mtu > MELODI_FRAME_MTU_MAX)
        return -EPROTO;
    *info = link;
    return 0;
}

u32 melodi_core_frame_mtu(struct net_device *dev)
{
    struct melodi_link_info info;

    if (melodi_core_link_info(dev, &info))
        return 0;
    return info.frame_mtu;
}

struct net_device *melodi_attach_transport(struct device *parent,
                                           size_t driver_private_size,
                                           const struct melodi_link_ops *ops,
                                           struct module *owner)
{
    struct melodi_device_entry *entry;
    struct melodi_device *melodi;
    struct melodi_transport *transport;
    struct net_device *dev;

    if (!ops || !ops->xmit || !owner ||
        driver_private_size > KMALLOC_MAX_SIZE - sizeof(*transport))
        return ERR_PTR(-EINVAL);
    transport = kzalloc(struct_size(transport, private_data,
                                    driver_private_size), GFP_KERNEL);
    if (!transport)
        return ERR_PTR(-ENOMEM);
    transport->ops = ops;
    transport->owner = owner;
    transport->parent = parent;
    transport->private_size = driver_private_size;
    refcount_set(&transport->references, 1);
    init_completion(&transport->released);
    for (;;) {
        dev = NULL;
        mutex_lock(&melodi_devices_lock);
        list_for_each_entry(entry, &melodi_devices, node) {
            melodi = netdev_priv(entry->dev);
            mutex_lock(&melodi->lock);
            if (!melodi->transport && !melodi->radio_serial[0]) {
                melodi->transport = transport;
                melodi->link_state = MELODI_LINK_CONFIGURING;
                melodi->link_failure = MELODI_LINK_FAILURE_NONE;
                melodi->link_error = 0;
                dev = entry->dev;
                dev_hold(dev);
                mutex_unlock(&melodi->lock);
                break;
            }
            mutex_unlock(&melodi->lock);
        }
        mutex_unlock(&melodi_devices_lock);
        if (dev) {
            netif_dormant_on(dev);
            dev_put(dev);
            return dev;
        }
        dev = melodi_alloc_device(false);
        if (IS_ERR(dev)) {
            kfree(transport);
            return dev;
        }
        melodi = netdev_priv(dev);
        mutex_lock(&melodi->lock);
        if (!melodi->transport) {
            melodi->transport = transport;
            melodi->link_state = MELODI_LINK_CONFIGURING;
            melodi->link_failure = MELODI_LINK_FAILURE_NONE;
            melodi->link_error = 0;
            mutex_unlock(&melodi->lock);
            netif_dormant_on(dev);
            return dev;
        }
        mutex_unlock(&melodi->lock);
    }
}
EXPORT_SYMBOL_GPL(melodi_attach_transport);

static bool melodi_radio_serial_valid(const char *radio_serial)
{
    size_t length;
    size_t index;

    if (!radio_serial)
        return false;
    length = strnlen(radio_serial, MELODI_RADIO_SERIAL_MAX + 1);
    if (!length || length > MELODI_RADIO_SERIAL_MAX)
        return false;
    for (index = 0; index < length; index++)
        if (radio_serial[index] < 0x21 || radio_serial[index] > 0x7e ||
            radio_serial[index] == ',')
            return false;
    return true;
}

int melodi_set_transport_selector(struct net_device *dev,
                                  const char *radio_serial)
{
    struct melodi_device_entry *entry;
    struct melodi_device *melodi;
    int error = 0;

    if (!melodi_device_is(dev) || !melodi_radio_serial_valid(radio_serial))
        return -EINVAL;
    mutex_lock(&melodi_devices_lock);
    list_for_each_entry(entry, &melodi_devices, node) {
        struct melodi_device *candidate = netdev_priv(entry->dev);

        if (entry->dev != dev &&
            !strcmp(candidate->radio_serial, radio_serial)) {
            error = -EEXIST;
            goto unlock;
        }
    }
    melodi = netdev_priv(dev);
    mutex_lock(&melodi->lock);
    if (melodi->transport && strcmp(melodi->radio_serial, radio_serial))
        error = -EBUSY;
    else
        strscpy(melodi->radio_serial, radio_serial,
                sizeof(melodi->radio_serial));
    mutex_unlock(&melodi->lock);
unlock:
    mutex_unlock(&melodi_devices_lock);
    return error;
}
EXPORT_SYMBOL_GPL(melodi_set_transport_selector);

struct net_device *melodi_attach_selected_transport(
    struct device *parent, const char *radio_serial,
    size_t driver_private_size, const struct melodi_link_ops *ops,
    struct module *owner)
{
    struct melodi_device_entry *entry;
    struct melodi_transport *transport;
    struct net_device *dev = NULL;
    int error = -ENODEV;

    if (!ops || !ops->xmit || !owner ||
        !melodi_radio_serial_valid(radio_serial) ||
        driver_private_size > KMALLOC_MAX_SIZE - sizeof(*transport))
        return ERR_PTR(-EINVAL);
    transport = kzalloc(struct_size(transport, private_data,
                                    driver_private_size), GFP_KERNEL);
    if (!transport)
        return ERR_PTR(-ENOMEM);
    transport->ops = ops;
    transport->owner = owner;
    transport->parent = parent;
    transport->private_size = driver_private_size;
    refcount_set(&transport->references, 1);
    init_completion(&transport->released);
    mutex_lock(&melodi_devices_lock);
    list_for_each_entry(entry, &melodi_devices, node) {
        struct melodi_device *melodi = netdev_priv(entry->dev);

        mutex_lock(&melodi->lock);
        if (strcmp(melodi->radio_serial, radio_serial)) {
            mutex_unlock(&melodi->lock);
            continue;
        }
        if (melodi->transport) {
            error = -EBUSY;
            mutex_unlock(&melodi->lock);
            break;
        }
        melodi->transport = transport;
        melodi->link_state = MELODI_LINK_CONFIGURING;
        melodi->link_failure = MELODI_LINK_FAILURE_NONE;
        melodi->link_error = 0;
        dev = entry->dev;
        mutex_unlock(&melodi->lock);
        break;
    }
    mutex_unlock(&melodi_devices_lock);
    if (!dev) {
        kfree(transport);
        return ERR_PTR(error);
    }
    netif_dormant_on(dev);
    return dev;
}
EXPORT_SYMBOL_GPL(melodi_attach_selected_transport);

/**
 * melodi_link_attach - bind transport operations to an rtnl-created device
 * @dev: device allocated with melodi_link_setup() and already registered
 * @ops: sleepable transport operations
 * @owner: module owning @ops
 * @driver_private_size: octets reserved for melodi_transport_priv()
 */
int melodi_link_attach(struct net_device *dev,
                       const struct melodi_link_ops *ops,
                       struct module *owner, size_t driver_private_size)
{
    struct melodi_transport *transport;
    struct melodi_device *melodi;

    if (!melodi_device_is(dev) || !ops || !ops->xmit || !owner ||
        driver_private_size > KMALLOC_MAX_SIZE - sizeof(*transport))
        return -EINVAL;
    transport = kzalloc(struct_size(transport, private_data,
                                    driver_private_size), GFP_KERNEL);
    if (!transport)
        return -ENOMEM;
    transport->ops = ops;
    transport->owner = owner;
    transport->parent = NULL;
    transport->private_size = driver_private_size;
    refcount_set(&transport->references, 1);
    init_completion(&transport->released);
    melodi = netdev_priv(dev);
    mutex_lock(&melodi->lock);
    if (melodi->transport) {
        mutex_unlock(&melodi->lock);
        kfree(transport);
        return -EBUSY;
    }
    melodi->transport = transport;
    melodi->link_state = MELODI_LINK_CONFIGURING;
    melodi->link_failure = MELODI_LINK_FAILURE_NONE;
    melodi->link_error = 0;
    mutex_unlock(&melodi->lock);
    netif_dormant_on(dev);
    return 0;
}
EXPORT_SYMBOL_GPL(melodi_link_attach);

/**
 * melodi_link_release - stop core work before an rtnl device is unregistered
 * @dev: device previously passed to melodi_link_attach()
 */
void melodi_link_release(struct net_device *dev)
{
    struct melodi_device *melodi;

    if (!melodi_device_is(dev))
        return;
    melodi = netdev_priv(dev);
    melodi_detach_transport(dev);
    melodi_netlink_interface_removed(dev);
    melodi_logical_stop(melodi, -ENODEV);
    melodi_queue_stop(dev);
    melodi_discovery_stop(melodi);
    melodi_data_stop(melodi);
    if (melodi->identity_key) {
        key_put(melodi->identity_key);
        melodi->identity_key = NULL;
    }
}
EXPORT_SYMBOL_GPL(melodi_link_release);

void *melodi_transport_priv(struct net_device *dev)
{
    struct melodi_device *melodi;
    struct melodi_transport *transport;

    if (!dev || dev->netdev_ops != &melodi_netdev_ops)
        return NULL;
    melodi = netdev_priv(dev);
    transport = READ_ONCE(melodi->transport);
    return transport ? transport->private_data : NULL;
}
EXPORT_SYMBOL_GPL(melodi_transport_priv);

int melodi_transport_configure(struct net_device *dev)
{
    struct melodi_link_config config = {};
    struct melodi_device *melodi;
    struct melodi_transport *transport;
    int error;

    if (!dev || dev->netdev_ops != &melodi_netdev_ops)
        return -EINVAL;
    melodi = netdev_priv(dev);
    mutex_lock(&melodi->lock);
    transport = melodi->transport;
    if (!melodi->identity_ready) {
        mutex_unlock(&melodi->lock);
        return -EAGAIN;
    }
    if (!transport || !transport->ops || !transport->ops->configure ||
        !refcount_inc_not_zero(&transport->references)) {
        mutex_unlock(&melodi->lock);
        return -EOPNOTSUPP;
    }
    memcpy(config.mesh_domain, melodi->mesh_domain,
           sizeof(config.mesh_domain));
    config.locator = melodi->local_native_locator;
    melodi->transport_ready = false;
    melodi->local_link_locator = 0;
    melodi->link_state = MELODI_LINK_CONFIGURING;
    melodi->link_failure = MELODI_LINK_FAILURE_NONE;
    melodi->link_error = 0;
    mutex_unlock(&melodi->lock);
    netif_carrier_off(dev);
    netif_dormant_on(dev);
    netif_tx_stop_all_queues(dev);
    melodi_logical_stop(melodi, -ENETDOWN);
    melodi_queue_fail(dev, -ENETDOWN);
    melodi_data_fail_pending(dev, -ENETDOWN);
    error = transport->ops->configure(dev, &config, NULL);
    if (refcount_dec_and_test(&transport->references))
        complete(&transport->released);
    if (error)
        melodi_link_failed(dev, MELODI_LINK_FAILURE_TRANSPORT, error);
    return error;
}
EXPORT_SYMBOL_GPL(melodi_transport_configure);

void melodi_detach_transport(struct net_device *dev)
{
    struct melodi_device *melodi;
    struct melodi_transport *transport;
    bool persistent;

    if (!dev || dev->netdev_ops != &melodi_netdev_ops)
        return;
    melodi = netdev_priv(dev);
    netif_carrier_off(dev);
    netif_tx_disable(dev);
    melodi_logical_stop(melodi, -ENETDOWN);
    melodi_queue_fail(dev, -ENETDOWN);
    melodi_data_fail_pending(dev, -ENETDOWN);
    mutex_lock(&melodi->lock);
    transport = melodi->transport;
    if (!transport) {
        mutex_unlock(&melodi->lock);
        return;
    }
    melodi->transport = NULL;
    melodi->transport_ready = false;
    melodi->local_link_locator = 0;
    melodi->link_state = MELODI_LINK_DISCONNECTED;
    melodi->link_failure = MELODI_LINK_FAILURE_NONE;
    melodi->link_error = 0;
    persistent = melodi->persistent;
    mutex_unlock(&melodi->lock);
    netif_dormant_off(dev);
    if (!refcount_dec_and_test(&transport->references))
        wait_for_completion(&transport->released);
    mutex_lock(&melodi->lock);
    melodi_data_reset_locked(melodi);
    melodi_discovery_reset_locked(melodi);
    mutex_unlock(&melodi->lock);
    kfree(transport);
    if (!persistent)
        melodi_unregister_device(dev);
}
EXPORT_SYMBOL_GPL(melodi_detach_transport);

void melodi_link_ready(struct net_device *dev, bool ready,
                       u32 local_locator)
{
    struct melodi_device *melodi;
    bool link_ready;
    bool notify;

    if (!dev || dev->netdev_ops != &melodi_netdev_ops ||
        (ready && (!local_locator ||
                   local_locator == MELODI_LINK_LOCATOR_BROADCAST)))
        return;
    melodi = netdev_priv(dev);
    notify = !ready && netif_carrier_ok(dev);
    mutex_lock(&melodi->lock);
    melodi->transport_ready = ready;
    melodi->local_link_locator = ready ? local_locator : 0;
    melodi->link_failure = MELODI_LINK_FAILURE_NONE;
    melodi->link_error = 0;
    if (ready && melodi->identity_ready)
        melodi->link_state = MELODI_LINK_READY;
    else
        melodi->link_state = MELODI_LINK_CONFIGURING;
    link_ready = ready && melodi->identity_ready;
    mutex_unlock(&melodi->lock);
    if (link_ready) {
        netif_dormant_off(dev);
        netif_carrier_on(dev);
        melodi_queue_start(dev);
        if (netif_running(dev)) {
            melodi_logical_start(melodi);
            netif_tx_wake_all_queues(dev);
        }
    } else {
        netif_carrier_off(dev);
        netif_dormant_on(dev);
        netif_tx_stop_all_queues(dev);
        melodi_logical_stop(melodi, -ENETDOWN);
        melodi_queue_pause(dev);
        if (notify)
            melodi_netlink_link_error(dev, -ENETDOWN);
    }
    if (link_ready && netif_running(dev))
        melodi_discovery_announce(dev);
}
EXPORT_SYMBOL_GPL(melodi_link_ready);

void melodi_link_failed(struct net_device *dev,
                        enum melodi_link_failure failure, int error)
{
    struct melodi_device *melodi;
    bool notify;

    if (!dev || dev->netdev_ops != &melodi_netdev_ops ||
        failure <= MELODI_LINK_FAILURE_NONE ||
        failure > MELODI_LINK_FAILURE_MAX)
        return;
    if (error >= 0)
        error = -EIO;
    melodi = netdev_priv(dev);
    notify = netif_carrier_ok(dev);
    netif_carrier_off(dev);
    netif_tx_stop_all_queues(dev);
    melodi_logical_stop(melodi, error);
    melodi_queue_fail(dev, error);
    if (notify)
        melodi_netlink_link_error(dev, error);
    mutex_lock(&melodi->lock);
    melodi->transport_ready = false;
    melodi->local_link_locator = 0;
    melodi->link_state = MELODI_LINK_FAILED;
    melodi->link_failure = failure;
    melodi->link_error = error;
    mutex_unlock(&melodi->lock);
    netif_dormant_off(dev);
}
EXPORT_SYMBOL_GPL(melodi_link_failed);

u32 melodi_core_abi_version(void)
{
    return MELODI_CORE_ABI_VERSION;
}
EXPORT_SYMBOL_GPL(melodi_core_abi_version);

int melodi_rx_frame(struct net_device *dev, const void *frame, size_t length,
                    const struct melodi_rx_meta *meta)
{
    struct melodi_device *melodi;
    struct melodi_wire_common header;
    int error;

    if (!dev || !frame || !meta || length == 0 ||
        length > MELODI_FRAME_MTU_MAX)
        return -EINVAL;
    melodi = netdev_priv(dev);
    error = melodi_wire_decode_common(frame, length, &header);
    if (error)
        return error;
    mutex_lock(&melodi->lock);
    if (!melodi->transport_ready || !meta->source_locator ||
        meta->source_locator == MELODI_LINK_LOCATOR_BROADCAST ||
        (header.destination_native_locator ==
             MELODI_NATIVE_LOCATOR_BROADCAST ?
             meta->destination_locator != MELODI_LINK_LOCATOR_BROADCAST :
             meta->destination_locator != melodi->local_link_locator))
        error = -EHOSTUNREACH;
    else
        error = 0;
    mutex_unlock(&melodi->lock);
    if (error) {
        dev->stats.rx_dropped++;
        return -EHOSTUNREACH;
    }
    melodi_netlink_monitor_frame(dev, MELODI_MONITOR_RX, frame, length, meta);
    if (header.frame_class == MELODI_WIRE_HELLO ||
        header.frame_class == MELODI_WIRE_CHALLENGE ||
        header.frame_class == MELODI_WIRE_RESPONSE ||
        header.frame_class == MELODI_WIRE_CONFLICT ||
        header.frame_class == MELODI_WIRE_CONTROL)
        error = melodi_discovery_receive(dev, frame, length, meta);
    else if (header.frame_class == MELODI_WIRE_DATA)
        error = melodi_data_receive(dev, frame, length, meta);
    else if (header.frame_class == MELODI_WIRE_ACK)
        error = melodi_data_receive_ack(dev, frame, length, meta);
    else
        error = -EOPNOTSUPP;
    if (error) {
        if (error == -EKEYREJECTED)
            atomic64_inc(&melodi->auth_failures);
        else if (error == -EALREADY)
            atomic64_inc(&melodi->replay_drops);
        return error;
    }
    dev->stats.rx_packets++;
    dev->stats.rx_bytes += length;
    return 0;
}
EXPORT_SYMBOL_GPL(melodi_rx_frame);

void melodi_tx_complete(struct net_device *dev, u64 cookie, int error)
{
    (void)cookie;
    if (!dev)
        return;
    if (error)
        dev->stats.tx_errors++;
}
EXPORT_SYMBOL_GPL(melodi_tx_complete);

static int __init melodi_core_init(void)
{
    struct net_device *dev;
    unsigned int index;
    int error;

    if (!interface_count || interface_count > 8 || radio_serial_count > 8)
        return -EINVAL;
    if (interface_count < radio_serial_count)
        interface_count = radio_serial_count;
    error = melodi_netlink_register();
    if (error)
        return error;
    for (index = 0; index < interface_count; index++) {
        dev = melodi_alloc_device(true);
        if (IS_ERR(dev)) {
            error = PTR_ERR(dev);
            goto unregister;
        }
        if (index < radio_serial_count) {
            error = melodi_set_transport_selector(dev,
                                                  radio_serials[index]);
            if (error)
                goto unregister;
        }
    }
    return 0;
unregister:
    while (!list_empty(&melodi_devices)) {
        struct melodi_device_entry *entry =
            list_first_entry(&melodi_devices,
                             struct melodi_device_entry, node);

        melodi_unregister_device(entry->dev);
    }
    melodi_netlink_unregister();
    return error;
}

static void __exit melodi_core_exit(void)
{
    struct melodi_device_entry *entry;
    struct melodi_device_entry *next;

    mutex_lock(&melodi_devices_lock);
    list_for_each_entry_safe(entry, next, &melodi_devices, node) {
        struct net_device *dev = entry->dev;
        struct melodi_device *melodi = netdev_priv(dev);

        list_del(&entry->node);
        kfree(entry);
        mutex_unlock(&melodi_devices_lock);
        melodi_netlink_interface_removed(dev);
        melodi_logical_stop(melodi, -ENODEV);
        melodi_queue_stop(dev);
        melodi_discovery_stop(melodi);
        melodi_data_stop(melodi);
        if (melodi->identity_key)
            key_put(melodi->identity_key);
        unregister_netdev(dev);
        mutex_lock(&melodi_devices_lock);
    }
    mutex_unlock(&melodi_devices_lock);
    melodi_netlink_unregister();
}

module_init(melodi_core_init);
module_exit(melodi_core_exit);

MODULE_AUTHOR("Melodi contributors");
MODULE_DESCRIPTION("Native Melodi protocol core");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1.0");
