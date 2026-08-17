/* SPDX-License-Identifier: GPL-2.0-only */
#include "internal.h"

#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/slab.h>

struct melodi_namespace_queue {
    struct list_head node;
    struct net *net;
    u32 messages;
    u32 bytes;
};

struct melodi_queue_notice {
    u64 binding_generation;
    u64 cookie;
    u32 binding_portid;
    u16 service;
    int error;
    bool active;
};

static LIST_HEAD(melodi_namespace_queues);
static DEFINE_MUTEX(melodi_queue_lock);

static const u8 melodi_priority_cycle[] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1,
    2, 2,
    3,
};

static u64 melodi_queue_now(void)
{
    return div_u64(ktime_get_boottime_ns(), NSEC_PER_MSEC);
}

static struct melodi_namespace_queue *melodi_namespace_queue_find(
    struct net *net)
{
    struct melodi_namespace_queue *queue;

    list_for_each_entry(queue, &melodi_namespace_queues, node)
        if (queue->net == net)
            return queue;
    return NULL;
}

static struct melodi_namespace_queue *melodi_namespace_queue_get(
    struct net *net)
{
    struct melodi_namespace_queue *queue;

    queue = melodi_namespace_queue_find(net);
    if (queue)
        return queue;
    queue = kzalloc(sizeof(*queue), GFP_KERNEL);
    if (!queue)
        return NULL;
    queue->net = get_net(net);
    list_add_tail(&queue->node, &melodi_namespace_queues);
    return queue;
}

static void melodi_namespace_queue_put(struct melodi_namespace_queue *queue)
{
    if (queue->messages)
        return;
    list_del(&queue->node);
    put_net(queue->net);
    kfree(queue);
}

static bool melodi_queue_has_peer(const struct melodi_device *melodi,
                                  u8 peer_index)
{
    unsigned int index;

    for (index = 0; index < MELODI_TX_QUEUE_LIMIT; index++)
        if (melodi->tx_queue[index].active &&
            !melodi->tx_queue[index].control &&
            melodi->tx_queue[index].peer_index == peer_index)
            return true;
    for (index = 0; index < MELODI_TX_RESERVATION_LIMIT; index++)
        if (melodi->tx_reservations[index].active &&
            melodi->tx_reservations[index].peer_index == peer_index)
            return true;
    return false;
}

static bool melodi_queue_has_flow(const struct melodi_device *melodi,
                                  u8 flow_index)
{
    unsigned int index;

    for (index = 0; index < MELODI_TX_QUEUE_LIMIT; index++)
        if (melodi->tx_queue[index].active &&
            !melodi->tx_queue[index].control &&
            melodi->tx_queue[index].flow_index == flow_index)
            return true;
    for (index = 0; index < MELODI_TX_RESERVATION_LIMIT; index++)
        if (melodi->tx_reservations[index].active &&
            melodi->tx_reservations[index].flow_index == flow_index)
            return true;
    return false;
}

static struct melodi_tx_reservation *melodi_reservation_find_locked(
    struct melodi_device *melodi, u64 id)
{
    unsigned int index;

    for (index = 0; index < MELODI_TX_RESERVATION_LIMIT; index++)
        if (melodi->tx_reservations[index].active &&
            melodi->tx_reservations[index].id == id)
            return &melodi->tx_reservations[index];
    return NULL;
}

static void melodi_reservation_remove_locked(
    struct melodi_device *melodi, struct melodi_tx_reservation *reservation)
{
    struct melodi_namespace_queue *namespace;
    u8 peer_index = reservation->peer_index;
    u8 flow_index = reservation->flow_index;

    namespace = melodi_namespace_queue_find(reservation->net);
    if (namespace) {
        namespace->messages -= reservation->count;
        namespace->bytes -= reservation->bytes;
    }
    melodi->tx_reserved_count -= reservation->count;
    melodi->tx_reserved_bytes -= reservation->bytes;
    if (reservation->pending_reserved)
        melodi->tx_pending_reserved--;
    memset(reservation, 0, sizeof(*reservation));
    if (!melodi_queue_has_flow(melodi, flow_index))
        memset(&melodi->tx_flows[flow_index], 0,
               sizeof(melodi->tx_flows[flow_index]));
    if (!melodi_queue_has_peer(melodi, peer_index))
        memset(&melodi->tx_peers[peer_index], 0,
               sizeof(melodi->tx_peers[peer_index]));
    if (namespace)
        melodi_namespace_queue_put(namespace);
}

static struct sk_buff *melodi_queue_remove_locked(
    struct melodi_device *melodi, struct melodi_tx_queue_entry *entry)
{
    struct melodi_namespace_queue *namespace;
    struct sk_buff *frame = entry->frame;
    u8 peer_index = entry->peer_index;
    u8 flow_index = entry->flow_index;
    unsigned int length = entry->length;
    bool control = entry->control;

    namespace = melodi_namespace_queue_find(entry->net);
    if (namespace) {
        namespace->messages--;
        namespace->bytes -= length;
    }
    melodi->tx_queue_count--;
    melodi->tx_queue_bytes -= length;
    memset(entry, 0, sizeof(*entry));
    if (!control && !melodi_queue_has_flow(melodi, flow_index))
        memset(&melodi->tx_flows[flow_index], 0,
               sizeof(melodi->tx_flows[flow_index]));
    if (!control && !melodi_queue_has_peer(melodi, peer_index))
        memset(&melodi->tx_peers[peer_index], 0,
               sizeof(melodi->tx_peers[peer_index]));
    if (namespace)
        melodi_namespace_queue_put(namespace);
    return frame;
}

static void melodi_queue_notice_entry(
    struct melodi_queue_notice *notice,
    const struct melodi_tx_queue_entry *entry, int error)
{
    if (notice->active || entry->terminal_notified)
        return;
    notice->binding_portid = entry->binding_portid;
    notice->binding_generation = entry->binding_generation;
    notice->service = entry->service;
    notice->cookie = entry->metadata.cookie;
    notice->error = error;
    notice->active = true;
}

static void melodi_queue_notice_reservation(
    struct melodi_queue_notice *notice,
    const struct melodi_tx_reservation *reservation, int error)
{
    notice->binding_portid = reservation->binding_portid;
    notice->binding_generation = reservation->binding_generation;
    notice->service = reservation->service;
    notice->cookie = reservation->cookie;
    notice->error = error;
    notice->active = true;
}

static void melodi_queue_notify(struct net_device *dev,
                                const struct melodi_queue_notice *notice)
{
    if (notice->active)
        melodi_netlink_delivery_error(
            dev, notice->binding_portid, notice->binding_generation,
            notice->service, notice->cookie, notice->error);
}

static bool melodi_queue_cancel_group_locked(
    struct melodi_device *melodi, u64 group_id,
    struct melodi_tx_queue_entry *owned, int error,
    struct melodi_queue_notice *notice)
{
    const struct melodi_tx_queue_entry *representative = NULL;
    struct melodi_node_id destination;
    u64 binding_generation;
    u64 message_id;
    u32 binding_portid;
    u16 service;
    unsigned int index;
    bool reliable;
    bool changed = false;

    for (index = 0; index < MELODI_TX_QUEUE_LIMIT; index++) {
        struct melodi_tx_queue_entry *entry = &melodi->tx_queue[index];

        if (!entry->active || entry->group_id != group_id)
            continue;
        if (!representative)
            representative = entry;
        melodi_queue_notice_entry(notice, entry, error);
    }
    if (!representative)
        return false;
    destination = representative->destination;
    binding_generation = representative->binding_generation;
    message_id = representative->message_id;
    binding_portid = representative->binding_portid;
    service = representative->service;
    reliable = representative->reliable;
    if (reliable)
        melodi_data_cancel_pending_locked(
            melodi, &destination, message_id, 0);
    for (index = 0; index < MELODI_TX_QUEUE_LIMIT; index++) {
        struct melodi_tx_queue_entry *entry = &melodi->tx_queue[index];
        struct sk_buff *frame;
        bool same_message;

        same_message = reliable && message_id && entry->reliable &&
            entry->message_id == message_id &&
            entry->binding_portid == binding_portid &&
            entry->binding_generation == binding_generation &&
            entry->service == service &&
            !memcmp(&entry->destination, &destination,
                    sizeof(destination));
        if (!entry->active ||
            (entry->group_id != group_id && !same_message))
            continue;
        changed = true;
        if (entry->in_flight && entry != owned) {
            entry->cancelled = true;
            entry->terminal_notified = true;
            continue;
        }
        frame = melodi_queue_remove_locked(melodi, entry);
        kfree_skb(frame);
        melodi->netdev->stats.tx_dropped++;
    }
    return changed;
}

static int melodi_queue_peer_locked(struct melodi_device *melodi, u32 locator,
                                    u8 *peer_index, bool *created)
{
    int empty = -1;
    unsigned int index;

    for (index = 0; index < MELODI_TX_FLOW_LIMIT; index++) {
        if (!melodi->tx_peers[index].active && empty < 0)
            empty = index;
        if (melodi->tx_peers[index].active &&
            melodi->tx_peers[index].locator == locator) {
            *peer_index = index;
            *created = false;
            return 0;
        }
    }
    if (empty < 0)
        return -ENOSPC;
    *peer_index = empty;
    *created = true;
    return 0;
}

static int melodi_queue_flow_locked(
    struct melodi_device *melodi, u32 locator,
    const struct melodi_queue_request *request, u8 *flow_index,
    bool *created)
{
    int empty = -1;
    unsigned int index;

    for (index = 0; index < MELODI_TX_FLOW_LIMIT; index++) {
        struct melodi_tx_flow_turn *flow = &melodi->tx_flows[index];

        if (!flow->active && empty < 0)
            empty = index;
        if (flow->active && flow->locator == locator &&
            flow->service == request->service &&
            flow->binding_portid == request->binding_portid &&
            flow->binding_generation == request->binding_generation) {
            *flow_index = index;
            *created = false;
            return 0;
        }
    }
    if (empty < 0)
        return -ENOSPC;
    *flow_index = empty;
    *created = true;
    return 0;
}

static int melodi_queue_capacity_locked(
    struct melodi_device *melodi, struct net *net, u32 locator,
    const struct melodi_queue_request *request, u16 count, u32 bytes,
    struct melodi_namespace_queue **namespace)
{
    u32 peer_count = 0;
    u32 service_count = 0;
    u32 binding_count = 0;
    u32 data_count = 0;
    unsigned int index;

    *namespace = melodi_namespace_queue_get(net);
    if (!*namespace)
        return -ENOMEM;
    if (count > MELODI_TX_QUEUE_LIMIT || bytes > MELODI_TX_BYTE_LIMIT ||
        count > MELODI_TX_NAMESPACE_LIMIT ||
        bytes > MELODI_TX_NAMESPACE_BYTE_LIMIT)
        return -ENOBUFS;
    if (!request->control &&
        (count > MELODI_TX_DATA_LIMIT ||
         count > MELODI_TX_PER_PEER_LIMIT ||
         count > MELODI_TX_PER_SERVICE_LIMIT ||
         count > MELODI_TX_PER_BINDING_LIMIT))
        return -ENOBUFS;
    for (index = 0; index < MELODI_TX_QUEUE_LIMIT; index++) {
        const struct melodi_tx_queue_entry *entry = &melodi->tx_queue[index];

        if (!entry->active)
            continue;
        if (!entry->control)
            data_count++;
        if (!request->control && !entry->control &&
            entry->metadata.destination_locator == locator)
            peer_count++;
        if (!request->control && !entry->control &&
            entry->service == request->service)
            service_count++;
        if (!request->control && !entry->control &&
            entry->binding_portid == request->binding_portid &&
            entry->binding_generation == request->binding_generation)
            binding_count++;
    }
    for (index = 0; index < MELODI_TX_RESERVATION_LIMIT; index++) {
        const struct melodi_tx_reservation *reservation =
            &melodi->tx_reservations[index];

        if (!reservation->active)
            continue;
        data_count += reservation->count;
        if (reservation->locator == locator)
            peer_count += reservation->count;
        if (reservation->service == request->service)
            service_count += reservation->count;
        if (reservation->binding_portid == request->binding_portid &&
            reservation->binding_generation == request->binding_generation)
            binding_count += reservation->count;
    }
    if (melodi->tx_queue_count + melodi->tx_reserved_count >
            MELODI_TX_QUEUE_LIMIT - count ||
        melodi->tx_queue_bytes + melodi->tx_reserved_bytes >
            MELODI_TX_BYTE_LIMIT - bytes ||
        (*namespace)->messages > MELODI_TX_NAMESPACE_LIMIT - count ||
        (*namespace)->bytes > MELODI_TX_NAMESPACE_BYTE_LIMIT - bytes)
        return -ENOBUFS;
    if (!request->control &&
        (data_count > MELODI_TX_DATA_LIMIT - count ||
         peer_count > MELODI_TX_PER_PEER_LIMIT - count ||
         service_count > MELODI_TX_PER_SERVICE_LIMIT - count ||
         binding_count > MELODI_TX_PER_BINDING_LIMIT - count))
        return -ENOBUFS;
    return 0;
}

static void melodi_reservation_schedule_locked(struct melodi_device *melodi,
                                               u64 now_ms)
{
    u64 next_ms = U64_MAX;
    unsigned int index;

    for (index = 0; index < MELODI_TX_RESERVATION_LIMIT; index++)
        if (melodi->tx_reservations[index].active)
            next_ms = min(next_ms,
                          melodi->tx_reservations[index].expires_ms);
    if (next_ms != U64_MAX)
        mod_delayed_work(system_wq, &melodi->tx_reservation_work,
                         msecs_to_jiffies(next_ms > now_ms ?
                                         next_ms - now_ms : 1));
}

static void melodi_reservation_work(struct work_struct *work)
{
    struct melodi_device *melodi = container_of(
        to_delayed_work(work), struct melodi_device, tx_reservation_work);
    struct melodi_tx_reservation *reservation;
    u64 binding_generation;
    u64 cookie;
    u64 now_ms;
    u32 binding_portid;
    u16 service;
    unsigned int index;

    for (;;) {
        reservation = NULL;
        mutex_lock(&melodi_queue_lock);
        now_ms = melodi_queue_now();
        for (index = 0; index < MELODI_TX_RESERVATION_LIMIT; index++)
            if (melodi->tx_reservations[index].active &&
                melodi->tx_reservations[index].expires_ms <= now_ms) {
                reservation = &melodi->tx_reservations[index];
                break;
            }
        if (!reservation) {
            melodi_reservation_schedule_locked(melodi, now_ms);
            mutex_unlock(&melodi_queue_lock);
            return;
        }
        binding_portid = reservation->binding_portid;
        binding_generation = reservation->binding_generation;
        service = reservation->service;
        cookie = reservation->cookie;
        melodi_reservation_remove_locked(melodi, reservation);
        atomic64_inc(&melodi->queue_expired);
        melodi->netdev->stats.tx_dropped++;
        mutex_unlock(&melodi_queue_lock);
        melodi_netlink_delivery_error(
            melodi->netdev, binding_portid, binding_generation, service,
            cookie, -ETIMEDOUT);
    }
}

int melodi_queue_reserve(struct net_device *dev, struct net *net, u32 locator,
                         const struct melodi_queue_request *request,
                         u16 count, u32 bytes, u32 logical_length, u64 cookie,
                         bool reliable, u16 active_pending, u64 *reservation_id)
{
    struct melodi_namespace_queue *namespace = NULL;
    struct melodi_tx_reservation *reservation = NULL;
    struct melodi_device *melodi = netdev_priv(dev);
    bool peer_created = false;
    bool flow_created = false;
    u64 now_ms;
    u8 peer_index = 0;
    u8 flow_index = 0;
    unsigned int index;
    int error;

    if (!dev || !net || !request || !reservation_id || !count || !bytes ||
        request->control || !request->ttl_ms ||
        request->reliable != reliable ||
        request->ttl_ms > MELODI_TTL_DEFAULT_MS)
        return -EINVAL;
    now_ms = melodi_queue_now();
    if (now_ms > U64_MAX - request->ttl_ms)
        return -EOVERFLOW;
    mutex_lock(&melodi_queue_lock);
    if (melodi->tx_queue_stopping) {
        error = -ENETDOWN;
        goto unlock;
    }
    if (reliable && active_pending + melodi->tx_pending_reserved >=
                        MELODI_PENDING_LIMIT) {
        error = -ENOSPC;
        goto unlock;
    }
    for (index = 0; index < MELODI_TX_RESERVATION_LIMIT; index++)
        if (!melodi->tx_reservations[index].active) {
            reservation = &melodi->tx_reservations[index];
            break;
        }
    if (!reservation) {
        error = -ENOBUFS;
        goto unlock;
    }
    error = melodi_queue_capacity_locked(
        melodi, net, locator, request, count, bytes, &namespace);
    if (error)
        goto unlock;
    error = melodi_queue_peer_locked(
        melodi, locator, &peer_index, &peer_created);
    if (!error)
        error = melodi_queue_flow_locked(
            melodi, locator, request, &flow_index, &flow_created);
    if (error)
        goto unlock;
    if (melodi->tx_reservation_sequence == U64_MAX) {
        error = -EOVERFLOW;
        goto unlock;
    }
    if (peer_created) {
        melodi->tx_peers[peer_index].locator = locator;
        melodi->tx_peers[peer_index].active = true;
    }
    if (flow_created) {
        melodi->tx_flows[flow_index].locator = locator;
        melodi->tx_flows[flow_index].binding_portid =
            request->binding_portid;
        melodi->tx_flows[flow_index].binding_generation =
            request->binding_generation;
        melodi->tx_flows[flow_index].service = request->service;
        melodi->tx_flows[flow_index].peer_index = peer_index;
        melodi->tx_flows[flow_index].active = true;
    }
    reservation->net = net;
    reservation->destination = request->destination;
    reservation->id = ++melodi->tx_reservation_sequence;
    reservation->expires_ms = now_ms + request->ttl_ms;
    reservation->binding_generation = request->binding_generation;
    reservation->cookie = cookie;
    reservation->session_epoch = request->session_epoch;
    reservation->locator = locator;
    reservation->source_locator = request->source_locator;
    reservation->binding_portid = request->binding_portid;
    reservation->identity_generation = request->identity_generation;
    reservation->bytes = bytes;
    reservation->logical_length = logical_length;
    reservation->count = count;
    reservation->service = request->service;
    reservation->destination_service = request->destination_service;
    reservation->priority = request->priority;
    reservation->peer_index = peer_index;
    reservation->flow_index = flow_index;
    reservation->pending_reserved = reliable;
    reservation->broadcast = request->broadcast;
    reservation->reliable = reliable;
    reservation->active = true;
    melodi->tx_reserved_count += count;
    melodi->tx_reserved_bytes += bytes;
    namespace->messages += count;
    namespace->bytes += bytes;
    if (reliable)
        melodi->tx_pending_reserved++;
    *reservation_id = reservation->id;
    melodi_reservation_schedule_locked(melodi, now_ms);
    error = 0;
unlock:
    if (error && flow_created && !melodi_queue_has_flow(melodi, flow_index))
        memset(&melodi->tx_flows[flow_index], 0,
               sizeof(melodi->tx_flows[flow_index]));
    if (error && peer_created && !melodi_queue_has_peer(melodi, peer_index))
        memset(&melodi->tx_peers[peer_index], 0,
               sizeof(melodi->tx_peers[peer_index]));
    if (error && namespace)
        melodi_namespace_queue_put(namespace);
    mutex_unlock(&melodi_queue_lock);
    return error;
}

void melodi_queue_reservation_cancel(struct net_device *dev, u64 id,
                                     int error, bool notify)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_tx_reservation *reservation;
    u64 binding_generation = 0;
    u64 cookie = 0;
    u32 binding_portid = 0;
    u16 service = 0;

    mutex_lock(&melodi_queue_lock);
    reservation = melodi_reservation_find_locked(melodi, id);
    if (reservation) {
        binding_generation = reservation->binding_generation;
        cookie = reservation->cookie;
        binding_portid = reservation->binding_portid;
        service = reservation->service;
        melodi_reservation_remove_locked(melodi, reservation);
    }
    mutex_unlock(&melodi_queue_lock);
    if (reservation && notify)
        melodi_netlink_delivery_error(dev, binding_portid,
                                      binding_generation, service,
                                      cookie, error);
}

int melodi_queue_reservation_pending(struct net_device *dev, u64 id)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_tx_reservation *reservation;
    int error = 0;

    mutex_lock(&melodi_queue_lock);
    reservation = melodi_reservation_find_locked(melodi, id);
    if (!reservation || !reservation->pending_reserved)
        error = -ENOENT;
    else {
        reservation->pending_reserved = false;
        melodi->tx_pending_reserved--;
    }
    mutex_unlock(&melodi_queue_lock);
    return error;
}

int melodi_queue_reservation_seal(struct net_device *dev, u64 id,
                                  const void *data, size_t length)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_tx_reservation *reservation;
    int error = 0;

    if (!data || !length)
        return -EINVAL;
    mutex_lock(&melodi_queue_lock);
    reservation = melodi_reservation_find_locked(melodi, id);
    if (!reservation || reservation->sealed)
        error = -ENOENT;
    else {
        reservation->tag = siphash(data, length, &melodi->logical_key);
        reservation->sealed = true;
    }
    mutex_unlock(&melodi_queue_lock);
    return error;
}

int melodi_queue_reservation_claim(struct net_device *dev, u64 id,
                                   const void *data, size_t length)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_tx_reservation *reservation;
    u64 tag;
    int error = 0;

    if (!data || !length)
        return -EINVAL;
    tag = siphash(data, length, &melodi->logical_key);
    mutex_lock(&melodi_queue_lock);
    reservation = melodi_reservation_find_locked(melodi, id);
    if (!reservation || !reservation->sealed || reservation->claimed ||
        reservation->tag != tag)
        error = -ENOENT;
    else
        reservation->claimed = true;
    mutex_unlock(&melodi_queue_lock);
    return error;
}

int melodi_queue_reservation_locator(struct net_device *dev, u64 id,
                                     u32 *locator)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_tx_reservation *reservation;
    int error = 0;

    if (!locator)
        return -EINVAL;
    mutex_lock(&melodi_queue_lock);
    reservation = melodi_reservation_find_locked(melodi, id);
    if (!reservation)
        error = -ENOENT;
    else
        *locator = reservation->locator;
    mutex_unlock(&melodi_queue_lock);
    return error;
}

int melodi_core_send_batch(struct net_device *dev, struct sk_buff **frames,
                           u16 count, const struct melodi_tx_meta *meta,
                           const struct melodi_queue_request *request)
{
    struct melodi_namespace_queue *namespace = NULL;
    struct melodi_device *melodi;
    unsigned int slots[MELODI_FRAGMENT_LIMIT];
    bool peer_created = false;
    bool flow_created = false;
    u64 expires_ms;
    u64 group_id;
    u64 now_ms;
    u32 bytes = 0;
    u8 peer_index = 0;
    u8 flow_index = 0;
    unsigned int found = 0;
    unsigned int index;
    int error;

    if (!dev || !frames || !meta || !request || !count ||
        count > MELODI_FRAGMENT_LIMIT || !request->ttl_ms ||
        request->ttl_ms > MELODI_TTL_DEFAULT_MS ||
        request->priority > MELODI_PRIORITY_MAX)
        return -EINVAL;
    if (!netif_running(dev) || !netif_carrier_ok(dev))
        return -ENETDOWN;
    melodi = netdev_priv(dev);
    for (index = 0; index < count; index++) {
        if (!frames[index] || !frames[index]->len)
            return -EINVAL;
        if (bytes > MELODI_TX_BYTE_LIMIT - frames[index]->len)
            return -EMSGSIZE;
        bytes += frames[index]->len;
    }
    now_ms = melodi_queue_now();
    if (now_ms > U64_MAX - request->ttl_ms)
        return -EOVERFLOW;
    if (!request->control) {
        mutex_lock(&melodi->lock);
        error = melodi_data_queue_valid_locked(
            melodi, &request->destination,
            request->destination_service, request->broadcast, meta,
            request->identity_generation, request->session_epoch);
        if (error) {
            mutex_unlock(&melodi->lock);
            return error;
        }
    }
    expires_ms = now_ms + request->ttl_ms;
    mutex_lock(&melodi_queue_lock);
    if (melodi->tx_queue_stopping) {
        error = -ENETDOWN;
        goto unlock;
    }
    error = melodi_queue_capacity_locked(
        melodi, dev_net(dev), meta->destination_locator, request, count,
        bytes, &namespace);
    if (error)
        goto unlock;
    if (melodi->tx_queue_sequence > U64_MAX - count ||
        melodi->tx_group_sequence == U64_MAX) {
        error = -EOVERFLOW;
        goto unlock;
    }
    for (index = 0; index < MELODI_TX_QUEUE_LIMIT && found < count; index++)
        if (!melodi->tx_queue[index].active)
            slots[found++] = index;
    if (found != count) {
        error = -ENOBUFS;
        goto unlock;
    }
    if (!request->control) {
        error = melodi_queue_peer_locked(
            melodi, meta->destination_locator, &peer_index, &peer_created);
        if (!error)
            error = melodi_queue_flow_locked(
                melodi, meta->destination_locator, request, &flow_index,
                &flow_created);
        if (error)
            goto unlock;
    }
    if (peer_created) {
        melodi->tx_peers[peer_index].locator = meta->destination_locator;
        melodi->tx_peers[peer_index].active = true;
    }
    if (flow_created) {
        melodi->tx_flows[flow_index].locator = meta->destination_locator;
        melodi->tx_flows[flow_index].binding_portid =
            request->binding_portid;
        melodi->tx_flows[flow_index].binding_generation =
            request->binding_generation;
        melodi->tx_flows[flow_index].service = request->service;
        melodi->tx_flows[flow_index].peer_index = peer_index;
        melodi->tx_flows[flow_index].active = true;
    }
    group_id = ++melodi->tx_group_sequence;
    for (index = 0; index < count; index++) {
        struct melodi_tx_queue_entry *entry =
            &melodi->tx_queue[slots[index]];

        entry->frame = frames[index];
        entry->net = namespace->net;
        entry->metadata = *meta;
        entry->sequence = ++melodi->tx_queue_sequence;
        entry->group_id = group_id;
        entry->destination = request->destination;
        entry->message_id = request->message_id;
        entry->session_epoch = request->session_epoch;
        entry->expires_ms = expires_ms;
        entry->binding_portid = request->binding_portid;
        entry->binding_generation = request->binding_generation;
        entry->identity_generation = request->identity_generation;
        entry->length = frames[index]->len;
        entry->service = request->service;
        entry->destination_service = request->destination_service;
        entry->priority = request->priority;
        entry->peer_index = peer_index;
        entry->flow_index = flow_index;
        entry->control = request->control;
        entry->broadcast = request->broadcast;
        entry->reliable = request->reliable;
        entry->active = true;
        melodi->tx_queue_count++;
        melodi->tx_queue_bytes += frames[index]->len;
        namespace->messages++;
        namespace->bytes += frames[index]->len;
        frames[index] = NULL;
    }
    mod_delayed_work(system_wq, &melodi->tx_queue_work, 0);
    if (melodi->tx_queue_count >= MELODI_TX_HIGH_WATER)
        netif_tx_stop_all_queues(dev);
unlock:
    if (error && namespace)
        melodi_namespace_queue_put(namespace);
    mutex_unlock(&melodi_queue_lock);
    if (!request->control)
        mutex_unlock(&melodi->lock);
    return error;
}

int melodi_core_send_batch_reserved(
    struct net_device *dev, struct sk_buff **frames, u16 count,
    const struct melodi_tx_meta *meta,
    const struct melodi_queue_request *request, u64 reservation_id)
{
    struct melodi_tx_reservation *reservation;
    struct melodi_device *melodi;
    unsigned int slots[MELODI_FRAGMENT_LIMIT];
    struct net *net;
    u64 expires_ms;
    u64 group_id;
    u32 logical_length;
    u32 bytes = 0;
    u8 peer_index;
    u8 flow_index;
    unsigned int found = 0;
    unsigned int index;
    int error = 0;

    if (!dev || !frames || !meta || !request || !reservation_id || !count ||
        count > MELODI_FRAGMENT_LIMIT || request->control)
        return -EINVAL;
    if (!netif_running(dev) || !netif_carrier_ok(dev))
        return -ENETDOWN;
    for (index = 0; index < count; index++) {
        if (!frames[index] || !frames[index]->len)
            return -EINVAL;
        if (bytes > MELODI_TX_BYTE_LIMIT - frames[index]->len)
            return -EMSGSIZE;
        bytes += frames[index]->len;
    }
    melodi = netdev_priv(dev);
    mutex_lock(&melodi->lock);
    error = melodi_data_queue_valid_locked(
        melodi, &request->destination, request->destination_service,
        request->broadcast, meta, request->identity_generation,
        request->session_epoch);
    if (error) {
        mutex_unlock(&melodi->lock);
        return error;
    }
    mutex_lock(&melodi_queue_lock);
    reservation = melodi_reservation_find_locked(melodi, reservation_id);
    if (!reservation) {
        error = -ENOENT;
        goto unlock;
    }
    if (melodi->tx_queue_stopping) {
        error = -ENETDOWN;
        goto unlock;
    }
    if (reservation->count != count || reservation->bytes != bytes ||
        reservation->locator != meta->destination_locator ||
        reservation->binding_portid != request->binding_portid ||
        reservation->binding_generation != request->binding_generation ||
        reservation->service != request->service ||
        reservation->destination_service != request->destination_service ||
        reservation->broadcast != request->broadcast ||
        reservation->reliable != request->reliable ||
        reservation->identity_generation != request->identity_generation ||
        reservation->source_locator != request->source_locator ||
        reservation->session_epoch != request->session_epoch ||
        memcmp(&reservation->destination, &request->destination,
               sizeof(request->destination)) ||
        reservation->priority != request->priority ||
        reservation->pending_reserved || !reservation->claimed) {
        error = -ESTALE;
        goto unlock;
    }
    for (index = 0; index < MELODI_TX_QUEUE_LIMIT && found < count; index++)
        if (!melodi->tx_queue[index].active)
            slots[found++] = index;
    if (found != count) {
        error = -ENOBUFS;
        goto unlock;
    }
    if (melodi->tx_queue_sequence > U64_MAX - count ||
        melodi->tx_group_sequence == U64_MAX) {
        error = -EOVERFLOW;
        goto unlock;
    }
    net = reservation->net;
    expires_ms = reservation->expires_ms;
    logical_length = reservation->logical_length;
    peer_index = reservation->peer_index;
    flow_index = reservation->flow_index;
    group_id = ++melodi->tx_group_sequence;
    melodi->tx_reserved_count -= count;
    melodi->tx_reserved_bytes -= bytes;
    memset(reservation, 0, sizeof(*reservation));
    for (index = 0; index < count; index++) {
        struct melodi_tx_queue_entry *entry =
            &melodi->tx_queue[slots[index]];

        entry->frame = frames[index];
        entry->net = net;
        entry->metadata = *meta;
        entry->sequence = ++melodi->tx_queue_sequence;
        entry->group_id = group_id;
        entry->destination = request->destination;
        entry->message_id = request->message_id;
        entry->session_epoch = request->session_epoch;
        entry->expires_ms = expires_ms;
        entry->binding_portid = request->binding_portid;
        entry->binding_generation = request->binding_generation;
        entry->identity_generation = request->identity_generation;
        entry->length = frames[index]->len;
        entry->service = request->service;
        entry->destination_service = request->destination_service;
        entry->priority = request->priority;
        entry->peer_index = peer_index;
        entry->flow_index = flow_index;
        entry->broadcast = request->broadcast;
        entry->reliable = request->reliable;
        entry->active = true;
        melodi->tx_queue_count++;
        melodi->tx_queue_bytes += frames[index]->len;
        frames[index] = NULL;
    }
    dev->stats.tx_packets++;
    dev->stats.tx_bytes += logical_length;
    mod_delayed_work(system_wq, &melodi->tx_queue_work, 0);
    if (melodi->tx_queue_count >= MELODI_TX_HIGH_WATER)
        netif_tx_stop_all_queues(dev);
unlock:
    mutex_unlock(&melodi_queue_lock);
    mutex_unlock(&melodi->lock);
    return error;
}

int melodi_core_send(struct net_device *dev, struct sk_buff *skb,
                     const struct melodi_tx_meta *meta)
{
    struct melodi_queue_request request = {
        .ttl_ms = MELODI_TX_CONTROL_TTL_MS,
        .service = MELODI_SERVICE_CONTROL,
        .priority = 0,
        .control = true,
    };
    struct sk_buff *frame = skb;

    return melodi_core_send_batch(dev, &frame, 1, meta, &request);
}

static int melodi_queue_oldest_control(const struct melodi_device *melodi,
                                       u64 now_ms)
{
    u64 sequence = U64_MAX;
    int selected = -1;
    unsigned int index;

    for (index = 0; index < MELODI_TX_QUEUE_LIMIT; index++)
        if (melodi->tx_queue[index].active &&
            !melodi->tx_queue[index].in_flight &&
            now_ms >= melodi->tx_queue[index].defer_until_ms &&
            melodi->tx_queue[index].control &&
            melodi->tx_queue[index].sequence < sequence) {
            sequence = melodi->tx_queue[index].sequence;
            selected = index;
        }
    return selected;
}

static int melodi_queue_priority(struct melodi_device *melodi, u64 now_ms,
                                 u8 *priority)
{
    unsigned int cycle;
    unsigned int index;

    for (cycle = 0; cycle < ARRAY_SIZE(melodi_priority_cycle); cycle++) {
        u8 slot = (melodi->tx_priority_slot + cycle) %
                  ARRAY_SIZE(melodi_priority_cycle);
        u8 candidate = melodi_priority_cycle[slot];

        for (index = 0; index < MELODI_TX_QUEUE_LIMIT; index++)
            if (melodi->tx_queue[index].active &&
                !melodi->tx_queue[index].in_flight &&
                now_ms >= melodi->tx_queue[index].defer_until_ms &&
                !melodi->tx_queue[index].control &&
                melodi->tx_queue[index].priority == candidate) {
                *priority = candidate;
                melodi->tx_priority_slot =
                    (slot + 1) % ARRAY_SIZE(melodi_priority_cycle);
                return 0;
            }
    }
    return -ENOENT;
}

static int melodi_queue_data(struct melodi_device *melodi, u64 now_ms)
{
    u64 peer_turn = U64_MAX;
    u64 peer_sequence = U64_MAX;
    u64 flow_turn = U64_MAX;
    u64 flow_sequence = U64_MAX;
    u64 sequence = U64_MAX;
    u8 priority;
    int peer_index = -1;
    int flow_index = -1;
    int selected = -1;
    unsigned int index;

    if (melodi_queue_priority(melodi, now_ms, &priority))
        return -1;
    for (index = 0; index < MELODI_TX_QUEUE_LIMIT; index++) {
        const struct melodi_tx_queue_entry *entry = &melodi->tx_queue[index];
        const struct melodi_tx_peer_turn *peer;

        if (!entry->active || entry->in_flight ||
            now_ms < entry->defer_until_ms || entry->control ||
            entry->priority != priority)
            continue;
        peer = &melodi->tx_peers[entry->peer_index];
        if (peer->turn < peer_turn ||
            (peer->turn == peer_turn && entry->sequence < peer_sequence)) {
            peer_turn = peer->turn;
            peer_sequence = entry->sequence;
            peer_index = entry->peer_index;
        }
    }
    for (index = 0; index < MELODI_TX_QUEUE_LIMIT; index++) {
        const struct melodi_tx_queue_entry *entry = &melodi->tx_queue[index];
        const struct melodi_tx_flow_turn *flow;

        if (!entry->active || entry->in_flight ||
            now_ms < entry->defer_until_ms || entry->control ||
            entry->priority != priority ||
            entry->peer_index != peer_index)
            continue;
        flow = &melodi->tx_flows[entry->flow_index];
        if (flow->turn < flow_turn ||
            (flow->turn == flow_turn && entry->sequence < flow_sequence)) {
            flow_turn = flow->turn;
            flow_sequence = entry->sequence;
            flow_index = entry->flow_index;
        }
    }
    for (index = 0; index < MELODI_TX_QUEUE_LIMIT; index++) {
        const struct melodi_tx_queue_entry *entry = &melodi->tx_queue[index];

        if (entry->active && !entry->in_flight &&
            now_ms >= entry->defer_until_ms && !entry->control &&
            entry->priority == priority && entry->peer_index == peer_index &&
            entry->flow_index == flow_index && entry->sequence < sequence) {
            sequence = entry->sequence;
            selected = index;
        }
    }
    if (selected < 0)
        return -1;
    if (melodi->tx_scheduler_turn == U64_MAX) {
        for (index = 0; index < MELODI_TX_FLOW_LIMIT; index++) {
            melodi->tx_peers[index].turn = 0;
            melodi->tx_flows[index].turn = 0;
        }
        melodi->tx_scheduler_turn = 0;
    }
    melodi->tx_peers[peer_index].turn = ++melodi->tx_scheduler_turn;
    melodi->tx_flows[flow_index].turn = melodi->tx_scheduler_turn;
    return selected;
}

/* A half-duplex radio cannot hear the reply it provoked while transmitting. */
static void melodi_queue_pacing(struct melodi_device *melodi, bool *busy,
                                u64 *guard_ms)
{
    struct melodi_link_info info;

    *busy = false;
    *guard_ms = 0;
    if (melodi_core_link_info(melodi->netdev, &info))
        return;
    *busy = info.transmit_pending != 0;
    *guard_ms = info.frame_pace_us / 2000;
}

static void melodi_queue_expire_locked(struct melodi_device *melodi,
                                       u64 now_ms,
                                       struct melodi_queue_notice *notice)
{
    unsigned int index;

    for (index = 0; index < MELODI_TX_QUEUE_LIMIT; index++)
        if (melodi->tx_queue[index].active &&
            !melodi->tx_queue[index].in_flight &&
            now_ms >= melodi->tx_queue[index].expires_ms) {
            struct sk_buff *frame;

            melodi_queue_notice_entry(notice, &melodi->tx_queue[index],
                                      -ETIMEDOUT);
            frame = melodi_queue_remove_locked(
                melodi, &melodi->tx_queue[index]);
            kfree_skb(frame);
            melodi->netdev->stats.tx_dropped++;
            atomic64_inc(&melodi->queue_expired);
        }
}

static unsigned long melodi_queue_next_delay_locked(
    const struct melodi_device *melodi, u64 now_ms)
{
    u64 wake_ms = U64_MAX;
    unsigned int index;

    for (index = 0; index < MELODI_TX_QUEUE_LIMIT; index++) {
        const struct melodi_tx_queue_entry *entry = &melodi->tx_queue[index];
        u64 candidate;

        if (!entry->active || entry->in_flight)
            continue;
        candidate = entry->expires_ms;
        if (entry->defer_until_ms > now_ms)
            candidate = min(candidate, entry->defer_until_ms);
        else
            return 1;
        wake_ms = min(wake_ms, candidate);
    }
    if (wake_ms == U64_MAX)
        return 0;
    if (wake_ms <= now_ms)
        return 1;
    return msecs_to_jiffies(min_t(u64, wake_ms - now_ms, U32_MAX));
}

static int melodi_queue_airtime_locked(
    struct melodi_device *melodi, const struct melodi_airtime_charge *charge,
    bool broadcast, u64 now_ms, struct melodi_airtime_window *after,
    struct melodi_airtime_window *broadcast_after, u64 *wait_ms)
{
    u64 total_wait = 0;
    u64 broadcast_wait = 0;
    int total_error;
    int broadcast_error = 0;

    *wait_ms = 0;
    *after = melodi->tx_airtime;
    *broadcast_after = melodi->tx_broadcast_airtime;
    if (!charge->duration_us)
        return 0;
    if (melodi->tx_airtime_budget_us != charge->budget_us ||
        melodi->tx_broadcast_budget_us != charge->broadcast_budget_us) {
        melodi_airtime_reset(&melodi->tx_airtime);
        melodi_airtime_reset(&melodi->tx_broadcast_airtime);
        melodi->tx_airtime_budget_us = charge->budget_us;
        melodi->tx_broadcast_budget_us = charge->broadcast_budget_us;
        *after = melodi->tx_airtime;
        *broadcast_after = melodi->tx_broadcast_airtime;
    }
    total_error = melodi_airtime_admit(
        after, now_ms, charge->budget_us, charge->duration_us, &total_wait);
    if (broadcast)
        broadcast_error = melodi_airtime_admit(
            broadcast_after, now_ms, charge->broadcast_budget_us,
            charge->duration_us, &broadcast_wait);
    if (total_error && total_error != -EAGAIN)
        return total_error;
    if (broadcast_error && broadcast_error != -EAGAIN)
        return broadcast_error;
    if (total_error == -EAGAIN || broadcast_error == -EAGAIN) {
        *wait_ms = max(total_wait, broadcast_wait);
        return -EAGAIN;
    }
    return 0;
}

static bool melodi_queue_transient(int error)
{
    return error == -EAGAIN || error == -ENOBUFS || error == -ENOSPC;
}

static void melodi_queue_work(struct work_struct *work)
{
    struct melodi_device *melodi = container_of(
        to_delayed_work(work), struct melodi_device, tx_queue_work);
    struct melodi_airtime_charge charge;
    struct melodi_queue_notice notice = {};
    struct melodi_queue_notice expired = {};
    struct melodi_tx_meta metadata;
    struct melodi_tx_queue_entry *entry;
    struct sk_buff *frame;
    unsigned long delay;
    u64 wait_ms = 0;
    u64 now_ms;
    u64 guard_ms;
    bool airtime_admitted = false;
    bool link_busy;
    bool broadcast;
    bool budget_checked = false;
    bool selected_control;
    int control;
    int selected;
    int error;

    melodi_queue_pacing(melodi, &link_busy, &guard_ms);
    mutex_lock(&melodi_queue_lock);
    if (melodi->tx_queue_stopping) {
        mutex_unlock(&melodi_queue_lock);
        return;
    }
    now_ms = melodi_queue_now();
    melodi_queue_expire_locked(melodi, now_ms, &expired);
    if (link_busy)
        melodi->tx_guard_until_ms = now_ms + guard_ms;
    if (melodi->tx_queue_count &&
        (link_busy || now_ms < melodi->tx_guard_until_ms)) {
        mod_delayed_work(system_wq, &melodi->tx_queue_work,
                         msecs_to_jiffies(100));
        mutex_unlock(&melodi_queue_lock);
        melodi_queue_notify(melodi->netdev, &expired);
        return;
    }
    if (melodi->tx_queue_count <= MELODI_TX_LOW_WATER &&
        netif_running(melodi->netdev) && netif_carrier_ok(melodi->netdev))
        netif_tx_wake_all_queues(melodi->netdev);
    control = melodi_queue_oldest_control(melodi, now_ms);
    selected = control >= 0 &&
               melodi->tx_control_burst < MELODI_TX_CONTROL_BURST ?
               control : -1;
    if (selected < 0) {
        selected = melodi_queue_data(melodi, now_ms);
        if (selected < 0)
            selected = control;
    }
    if (selected < 0) {
        delay = melodi_queue_next_delay_locked(melodi, now_ms);
        if (delay && !melodi->tx_queue_stopping)
            mod_delayed_work(system_wq, &melodi->tx_queue_work, delay);
        mutex_unlock(&melodi_queue_lock);
        melodi_queue_notify(melodi->netdev, &expired);
        return;
    }
    entry = &melodi->tx_queue[selected];
    entry->in_flight = true;
    metadata = entry->metadata;
    frame = entry->frame;
    selected_control = entry->control;
    broadcast = !entry->control &&
                metadata.destination_locator == MELODI_LINK_LOCATOR_BROADCAST;
    mutex_unlock(&melodi_queue_lock);
    melodi_queue_notify(melodi->netdev, &expired);

    if (!selected_control) {
        mutex_lock(&melodi->lock);
        mutex_lock(&melodi_queue_lock);
        if (entry->cancelled)
            error = -EACCES;
        else
            error = melodi_data_queue_valid_locked(
                melodi, &entry->destination,
                entry->destination_service, entry->broadcast,
                &entry->metadata, entry->identity_generation,
                entry->session_epoch);
        if (error) {
            melodi_queue_cancel_group_locked(
                melodi, entry->group_id, entry, error, &notice);
            if (melodi->tx_queue_count <= MELODI_TX_LOW_WATER &&
                netif_running(melodi->netdev) &&
                netif_carrier_ok(melodi->netdev))
                netif_tx_wake_all_queues(melodi->netdev);
            if (melodi->tx_queue_count && !melodi->tx_queue_stopping)
                mod_delayed_work(system_wq, &melodi->tx_queue_work, 1);
        }
        mutex_unlock(&melodi_queue_lock);
        mutex_unlock(&melodi->lock);
        if (error) {
            melodi_queue_notify(melodi->netdev, &notice);
            return;
        }
    }

    error = melodi_core_airtime(melodi->netdev, frame, &metadata, &charge);
    mutex_lock(&melodi_queue_lock);
    if (melodi->tx_queue_stopping) {
        frame = melodi_queue_remove_locked(melodi, entry);
        kfree_skb(frame);
        mutex_unlock(&melodi_queue_lock);
        return;
    }
    now_ms = melodi_queue_now();
    if (entry->cancelled)
        error = -EACCES;
    else if (now_ms >= entry->expires_ms)
        error = -ETIMEDOUT;
    else if (!error) {
        budget_checked = true;
        error = melodi_queue_airtime_locked(
            melodi, &charge, broadcast, now_ms, &melodi->tx_airtime_after,
            &melodi->tx_broadcast_after, &wait_ms);
    }
    if (error == -EAGAIN && budget_checked) {
        atomic64_inc(&melodi->duty_defers);
        entry->in_flight = false;
        entry->defer_until_ms = now_ms +
            min_t(u64, wait_ms, entry->expires_ms - now_ms);
        mod_delayed_work(system_wq, &melodi->tx_queue_work, 1);
        mutex_unlock(&melodi_queue_lock);
        return;
    }
    if (error) {
        melodi_queue_notice_entry(&notice, entry, error);
        frame = melodi_queue_remove_locked(melodi, entry);
        kfree_skb(frame);
        melodi->netdev->stats.tx_dropped++;
        if (error == -ETIMEDOUT)
            atomic64_inc(&melodi->queue_expired);
        if (melodi->tx_queue_count <= MELODI_TX_LOW_WATER &&
            netif_running(melodi->netdev) &&
            netif_carrier_ok(melodi->netdev))
            netif_tx_wake_all_queues(melodi->netdev);
        if (melodi->tx_queue_count)
            mod_delayed_work(system_wq, &melodi->tx_queue_work, 1);
        mutex_unlock(&melodi_queue_lock);
        melodi_queue_notify(melodi->netdev, &notice);
        return;
    }
    airtime_admitted = charge.duration_us != 0;
    mutex_unlock(&melodi_queue_lock);

    melodi_netlink_monitor_frame(melodi->netdev, MELODI_MONITOR_TX,
                                 frame->data, frame->len, NULL);
    error = melodi_core_xmit(melodi->netdev, frame, &metadata);
    mutex_lock(&melodi_queue_lock);
    now_ms = melodi_queue_now();
    if (error && melodi_queue_transient(error) &&
        !melodi->tx_queue_stopping && now_ms < entry->expires_ms) {
        entry->in_flight = false;
        entry->defer_until_ms = min_t(u64, entry->expires_ms, now_ms + 100);
    } else {
        if (error)
            melodi_queue_notice_entry(&notice, entry, error);
        melodi_queue_remove_locked(melodi, entry);
        if (error) {
            kfree_skb(frame);
            melodi->netdev->stats.tx_dropped++;
        } else {
            if (airtime_admitted) {
                melodi->tx_airtime = melodi->tx_airtime_after;
                melodi->tx_broadcast_airtime = melodi->tx_broadcast_after;
            }
            if (selected_control && melodi->tx_control_burst < U8_MAX)
                melodi->tx_control_burst++;
            else
                melodi->tx_control_burst = 0;
        }
        if (melodi->tx_queue_count <= MELODI_TX_LOW_WATER &&
            netif_running(melodi->netdev) &&
            netif_carrier_ok(melodi->netdev))
            netif_tx_wake_all_queues(melodi->netdev);
    }
    if (melodi->tx_queue_count && !melodi->tx_queue_stopping)
        mod_delayed_work(system_wq, &melodi->tx_queue_work, 1);
    mutex_unlock(&melodi_queue_lock);
    melodi_queue_notify(melodi->netdev, &notice);
}

void melodi_queue_state_changed(struct net_device *dev)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_queue_notice notice;
    unsigned int index;
    bool changed;
    int error;

    for (;;) {
        memset(&notice, 0, sizeof(notice));
        changed = false;
        mutex_lock(&melodi->lock);
        mutex_lock(&melodi_queue_lock);
        for (index = 0; index < MELODI_TX_RESERVATION_LIMIT; index++) {
            struct melodi_tx_reservation *reservation =
                &melodi->tx_reservations[index];
            struct melodi_tx_meta metadata;

            if (!reservation->active)
                continue;
            if (reservation->identity_generation) {
                memset(&metadata, 0, sizeof(metadata));
                metadata.source_locator = reservation->source_locator;
                metadata.destination_locator = reservation->locator;
                error = melodi_data_queue_valid_locked(
                    melodi, &reservation->destination,
                    reservation->destination_service,
                    reservation->broadcast, &metadata,
                    reservation->identity_generation,
                    reservation->session_epoch);
            } else {
                error = melodi_policy_check_message_locked(
                    melodi, &reservation->destination,
                    reservation->destination_service,
                    reservation->broadcast);
            }
            if (!error)
                continue;
            melodi_queue_notice_reservation(&notice, reservation, error);
            if (reservation->reliable)
                melodi_data_cancel_pending_locked(
                    melodi, &reservation->destination, 0,
                    reservation->id);
            melodi_reservation_remove_locked(melodi, reservation);
            melodi->netdev->stats.tx_dropped++;
            changed = true;
            break;
        }
        if (!changed)
            for (index = 0; index < MELODI_TX_QUEUE_LIMIT; index++) {
                struct melodi_tx_queue_entry *entry =
                    &melodi->tx_queue[index];

                if (!entry->active || entry->control || entry->cancelled)
                    continue;
                error = melodi_data_queue_valid_locked(
                    melodi, &entry->destination,
                    entry->destination_service, entry->broadcast,
                    &entry->metadata, entry->identity_generation,
                    entry->session_epoch);
                if (!error)
                    continue;
                changed = melodi_queue_cancel_group_locked(
                    melodi, entry->group_id, NULL, error, &notice);
                break;
            }
        if (changed) {
            if (melodi->tx_queue_count <= MELODI_TX_LOW_WATER &&
                netif_running(dev) && netif_carrier_ok(dev))
                netif_tx_wake_all_queues(dev);
            if (melodi->tx_queue_count && !melodi->tx_queue_stopping)
                mod_delayed_work(system_wq, &melodi->tx_queue_work, 1);
            melodi_reservation_schedule_locked(melodi,
                                               melodi_queue_now());
        }
        mutex_unlock(&melodi_queue_lock);
        mutex_unlock(&melodi->lock);
        melodi_queue_notify(dev, &notice);
        if (!changed)
            return;
    }
}

void melodi_queue_init(struct melodi_device *melodi)
{
    INIT_DELAYED_WORK(&melodi->tx_queue_work, melodi_queue_work);
    INIT_DELAYED_WORK(&melodi->tx_reservation_work,
                      melodi_reservation_work);
    melodi->tx_queue_stopping = true;
}

static void melodi_queue_drain(struct net_device *dev, int error)
{
    struct melodi_device *melodi = netdev_priv(dev);
    u64 reservation_id;
    unsigned int index;

    mutex_lock(&melodi_queue_lock);
    melodi->tx_queue_stopping = true;
    mutex_unlock(&melodi_queue_lock);
    cancel_delayed_work_sync(&melodi->tx_queue_work);
    cancel_delayed_work_sync(&melodi->tx_reservation_work);
    for (;;) {
        reservation_id = 0;
        mutex_lock(&melodi_queue_lock);
        for (index = 0; index < MELODI_TX_RESERVATION_LIMIT; index++)
            if (melodi->tx_reservations[index].active) {
                reservation_id = melodi->tx_reservations[index].id;
                break;
            }
        mutex_unlock(&melodi_queue_lock);
        if (!reservation_id)
            break;
        melodi_queue_reservation_cancel(dev, reservation_id, error, true);
    }
    mutex_lock(&melodi_queue_lock);
    for (index = 0; index < MELODI_TX_QUEUE_LIMIT; index++)
        if (melodi->tx_queue[index].active)
            kfree_skb(melodi_queue_remove_locked(
                melodi, &melodi->tx_queue[index]));
    memset(melodi->tx_peers, 0, sizeof(melodi->tx_peers));
    memset(melodi->tx_flows, 0, sizeof(melodi->tx_flows));
    melodi->tx_queue_bytes = 0;
    melodi->tx_queue_count = 0;
    melodi->tx_guard_until_ms = 0;
    melodi->tx_control_burst = 0;
    melodi->tx_airtime_budget_us = 0;
    melodi->tx_broadcast_budget_us = 0;
    melodi_airtime_reset(&melodi->tx_airtime);
    melodi_airtime_reset(&melodi->tx_broadcast_airtime);
    mutex_unlock(&melodi_queue_lock);
}

void melodi_queue_pause(struct net_device *dev)
{
    melodi_queue_drain(dev, -ENETDOWN);
}

void melodi_queue_start(struct net_device *dev)
{
    struct melodi_device *melodi = netdev_priv(dev);

    mutex_lock(&melodi_queue_lock);
    melodi->tx_queue_stopping = false;
    if (melodi->tx_queue_count)
        mod_delayed_work(system_wq, &melodi->tx_queue_work, 0);
    melodi_reservation_schedule_locked(melodi, melodi_queue_now());
    mutex_unlock(&melodi_queue_lock);
}

void melodi_queue_fail(struct net_device *dev, int error)
{
    melodi_queue_drain(dev, error);
}

void melodi_queue_stop(struct net_device *dev)
{
    melodi_queue_fail(dev, -ENODEV);
}

bool melodi_queue_message_queued(struct net_device *dev,
                                 const struct melodi_node_id *destination,
                                 u64 message_id, u32 binding_portid,
                                 u64 binding_generation, u16 service)
{
    struct melodi_device *melodi = netdev_priv(dev);
    unsigned int index;
    bool queued = false;

    mutex_lock(&melodi_queue_lock);
    for (index = 0; index < MELODI_TX_QUEUE_LIMIT; index++) {
        const struct melodi_tx_queue_entry *entry = &melodi->tx_queue[index];

        if (!entry->active || !entry->reliable ||
            entry->message_id != message_id ||
            entry->binding_portid != binding_portid ||
            entry->binding_generation != binding_generation ||
            entry->service != service ||
            memcmp(&entry->destination, destination, sizeof(*destination)))
            continue;
        queued = true;
        break;
    }
    mutex_unlock(&melodi_queue_lock);
    return queued;
}

void melodi_queue_stats(struct net_device *dev, u64 *frames, u64 *bytes,
                        u64 *airtime_us, u64 *broadcast_airtime_us)
{
    struct melodi_device *melodi = netdev_priv(dev);

    mutex_lock(&melodi_queue_lock);
    *frames = melodi->tx_queue_count + melodi->tx_reserved_count;
    *bytes = melodi->tx_queue_bytes + melodi->tx_reserved_bytes;
    *airtime_us = melodi->tx_airtime.total_us;
    *broadcast_airtime_us = melodi->tx_broadcast_airtime.total_us;
    mutex_unlock(&melodi_queue_lock);
}
