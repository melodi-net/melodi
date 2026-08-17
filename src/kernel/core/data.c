/* SPDX-License-Identifier: GPL-2.0-only */
#include "internal.h"

#include "wire.h"

#include <crypto/chacha20poly1305.h>
#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>

struct melodi_frame_batch {
    struct sk_buff *frames[MELODI_FRAGMENT_LIMIT];
    struct sk_buff *outgoing[MELODI_FRAGMENT_LIMIT];
};

struct melodi_order_batch {
    struct melodi_order_message messages[MELODI_ORDER_WINDOW + 1];
    u8 count;
};

static u64 melodi_reliability_now(void);
static void melodi_reassembly_schedule(struct melodi_device *melodi);
static void melodi_discovery_work(struct work_struct *work);
static int melodi_data_send_internal(
    struct net_device *dev, const struct melodi_node_id *destination,
    u16 source_service, u16 destination_service, const void *payload,
    size_t length, u32 flags, u64 cookie, u32 ttl_ms,
    u32 binding_portid, u64 binding_generation, u8 priority,
    bool queue_discovery, u64 reservation);

static struct melodi_peer *melodi_peer_by_node(struct melodi_device *melodi,
                                               const struct melodi_node_id *node)
{
    unsigned int index;

    for (index = 0; index < MELODI_PEER_LIMIT; index++)
        if (melodi->peers[index].authenticated &&
            !memcmp(&melodi->peers[index].node_id, node, sizeof(*node)))
            return &melodi->peers[index];
    return NULL;
}

static struct melodi_peer *melodi_peer_by_native_locator(
    struct melodi_device *melodi, u32 native_locator)
{
    unsigned int index;

    for (index = 0; index < MELODI_PEER_LIMIT; index++)
        if (melodi->peers[index].authenticated &&
            !melodi->peers[index].conflicted &&
            melodi->peers[index].native_locator == native_locator)
            return &melodi->peers[index];
    return NULL;
}

static void melodi_data_nonce(u8 nonce[24], u32 source_native_locator,
                              u32 generation, u64 counter, u64 message_id)
{
    nonce[0] = source_native_locator >> 24;
    nonce[1] = source_native_locator >> 16;
    nonce[2] = source_native_locator >> 8;
    nonce[3] = source_native_locator;
    nonce[4] = generation >> 24;
    nonce[5] = generation >> 16;
    nonce[6] = generation >> 8;
    nonce[7] = generation;
    nonce[8] = counter >> 56;
    nonce[9] = counter >> 48;
    nonce[10] = counter >> 40;
    nonce[11] = counter >> 32;
    nonce[12] = counter >> 24;
    nonce[13] = counter >> 16;
    nonce[14] = counter >> 8;
    nonce[15] = counter;
    nonce[16] = message_id >> 56;
    nonce[17] = message_id >> 48;
    nonce[18] = message_id >> 40;
    nonce[19] = message_id >> 32;
    nonce[20] = message_id >> 24;
    nonce[21] = message_id >> 16;
    nonce[22] = message_id >> 8;
    nonce[23] = message_id;
}

static void melodi_reassembly_clear(struct melodi_device *melodi,
                                    struct melodi_reassembly *entry)
{
    unsigned int index;

    if (!entry->active)
        return;
    for (index = 0; index < entry->fragment_count; index++)
        kfree_sensitive(entry->fragments[index].data);
    if (melodi->reassembly_bytes >= entry->received_length)
        melodi->reassembly_bytes -= entry->received_length;
    else
        melodi->reassembly_bytes = 0;
    memset(entry, 0, sizeof(*entry));
}

static struct melodi_receipt *melodi_receipt_find(
    struct melodi_device *melodi, const struct melodi_node_id *source,
    u32 generation, u64 session_epoch, u64 message_id)
{
    unsigned int index;

    for (index = 0; index < MELODI_RECEIPT_LIMIT; index++)
        if (melodi->receipts[index].active &&
            melodi->receipts[index].generation == generation &&
            melodi->receipts[index].session_epoch == session_epoch &&
            melodi->receipts[index].message_id == message_id &&
            !memcmp(&melodi->receipts[index].source, source,
                    sizeof(*source)))
            return &melodi->receipts[index];
    return NULL;
}

static int melodi_receipt_store(
    struct melodi_device *melodi, const struct melodi_node_id *source,
    u32 generation, u64 session_epoch, u64 message_id, u16 fragment_count,
    u64 bitmap, u8 status)
{
    struct melodi_receipt *receipt;
    struct melodi_receipt *oldest = NULL;
    unsigned int index;

    receipt = melodi_receipt_find(melodi, source, generation, session_epoch,
                                  message_id);
    if (!receipt)
        for (index = 0; index < MELODI_RECEIPT_LIMIT; index++) {
            if (!melodi->receipts[index].active) {
                receipt = &melodi->receipts[index];
                break;
            }
            if (!oldest || time_before(melodi->receipts[index].expires,
                                       oldest->expires))
                oldest = &melodi->receipts[index];
        }
    if (!receipt && oldest)
        receipt = oldest;
    if (!receipt)
        return -ENOSPC;
    memset(receipt, 0, sizeof(*receipt));
    receipt->source = *source;
    receipt->generation = generation;
    receipt->session_epoch = session_epoch;
    receipt->message_id = message_id;
    receipt->fragment_count = fragment_count;
    receipt->bitmap = bitmap;
    receipt->status = status;
    receipt->expires = jiffies +
                       msecs_to_jiffies(MELODI_RECEIPT_TIMEOUT_MS);
    receipt->active = true;
    return 0;
}

static void melodi_order_message_clear(struct melodi_device *melodi,
                                       struct melodi_order_message *message)
{
    if (!message->active)
        return;
    if (melodi->order_bytes >= message->length)
        melodi->order_bytes -= message->length;
    else
        melodi->order_bytes = 0;
    kfree_sensitive(message->payload);
    memset(message, 0, sizeof(*message));
}

static void melodi_order_flow_clear(struct melodi_device *melodi,
                                    u8 flow_index)
{
    unsigned int index;

    for (index = 0; index < MELODI_ORDER_BUFFER_LIMIT; index++)
        if (melodi->order_messages[index].active &&
            melodi->order_messages[index].flow_index == flow_index)
            melodi_order_message_clear(melodi,
                                       &melodi->order_messages[index]);
    memset(&melodi->order_rx[flow_index], 0,
           sizeof(melodi->order_rx[flow_index]));
}

void melodi_data_order_reset_locked(struct melodi_device *melodi)
{
    unsigned int index;

    for (index = 0; index < MELODI_ORDER_BUFFER_LIMIT; index++)
        melodi_order_message_clear(melodi, &melodi->order_messages[index]);
    memset(melodi->order_tx, 0, sizeof(melodi->order_tx));
    memset(melodi->order_rx, 0, sizeof(melodi->order_rx));
    melodi->order_bytes = 0;
}

void melodi_data_peer_reset_locked(struct melodi_device *melodi,
                                   const struct melodi_node_id *node_id)
{
    unsigned int index;

    for (index = 0; index < MELODI_REASSEMBLY_LIMIT; index++)
        if (melodi->reassemblies[index].active &&
            !memcmp(&melodi->reassemblies[index].source, node_id,
                    sizeof(*node_id)))
            melodi_reassembly_clear(melodi,
                                    &melodi->reassemblies[index]);
    for (index = 0; index < MELODI_RECEIPT_LIMIT; index++)
        if (melodi->receipts[index].active &&
            !memcmp(&melodi->receipts[index].source, node_id,
                    sizeof(*node_id)))
            memset(&melodi->receipts[index], 0,
                   sizeof(melodi->receipts[index]));
    for (index = 0; index < MELODI_ORDER_FLOW_LIMIT; index++) {
        if (melodi->order_rx[index].active &&
            !memcmp(&melodi->order_rx[index].source, node_id,
                    sizeof(*node_id)))
            melodi_order_flow_clear(melodi, index);
        if (melodi->order_tx[index].active &&
            !memcmp(&melodi->order_tx[index].destination, node_id,
                    sizeof(*node_id)))
            memset(&melodi->order_tx[index], 0,
                   sizeof(melodi->order_tx[index]));
    }
}

static struct melodi_order_message *melodi_order_message_find(
    struct melodi_device *melodi, u8 flow_index, u32 marker)
{
    unsigned int index;

    for (index = 0; index < MELODI_ORDER_BUFFER_LIMIT; index++)
        if (melodi->order_messages[index].active &&
            melodi->order_messages[index].flow_index == flow_index &&
            melodi->order_messages[index].marker == marker)
            return &melodi->order_messages[index];
    return NULL;
}

static struct melodi_order_message *melodi_order_message_empty(
    struct melodi_device *melodi)
{
    unsigned int index;

    for (index = 0; index < MELODI_ORDER_BUFFER_LIMIT; index++)
        if (!melodi->order_messages[index].active)
            return &melodi->order_messages[index];
    return NULL;
}

static int melodi_order_detach_locked(struct melodi_device *melodi,
                                      u8 flow_index, u32 marker, u8 count,
                                      struct melodi_order_batch *batch)
{
    struct melodi_order_message *message;
    u32 cursor = marker;
    u8 index;

    if (count > ARRAY_SIZE(batch->messages) - batch->count)
        return -EOVERFLOW;
    for (index = 0; index < count; index++) {
        if (!melodi_order_message_find(melodi, flow_index, cursor))
            return -EIO;
        cursor = melodi_order_next(cursor);
    }
    cursor = marker;
    for (index = 0; index < count; index++) {
        message = melodi_order_message_find(melodi, flow_index, cursor);
        batch->messages[batch->count++] = *message;
        if (melodi->order_bytes >= message->length)
            melodi->order_bytes -= message->length;
        else
            melodi->order_bytes = 0;
        memset(message, 0, sizeof(*message));
        cursor = melodi_order_next(cursor);
    }
    return 0;
}

static int melodi_order_tx_marker_locked(
    struct melodi_device *melodi, const struct melodi_node_id *destination,
    u16 source_service, u16 destination_service, u32 generation,
    u64 session_epoch, u32 *marker)
{
    struct melodi_order_tx_flow *empty = NULL;
    struct melodi_order_tx_flow *flow = NULL;
    unsigned int index;

    for (index = 0; index < MELODI_ORDER_FLOW_LIMIT; index++) {
        struct melodi_order_tx_flow *candidate = &melodi->order_tx[index];

        if (!candidate->active && !empty)
            empty = candidate;
        if (!candidate->active ||
            memcmp(&candidate->destination, destination,
                   sizeof(*destination)) ||
            candidate->source_service != source_service ||
            candidate->destination_service != destination_service)
            continue;
        flow = candidate;
        break;
    }
    if (flow && (flow->generation != generation ||
                 flow->session_epoch != session_epoch)) {
        memset(flow, 0, sizeof(*flow));
        empty = flow;
        flow = NULL;
    }
    if (!flow) {
        flow = empty;
        if (!flow)
            return -ENOSPC;
        memset(flow, 0, sizeof(*flow));
        flow->destination = *destination;
        flow->generation = generation;
        flow->session_epoch = session_epoch;
        flow->source_service = source_service;
        flow->destination_service = destination_service;
        flow->next_marker = 1;
        flow->active = true;
    }
    *marker = flow->next_marker;
    flow->next_marker = melodi_order_next(flow->next_marker);
    return 0;
}

static int melodi_order_rx_flow_locked(
    struct melodi_device *melodi, const struct melodi_node_id *source,
    u16 source_service, u16 destination_service, u32 generation,
    u64 session_epoch, u8 *flow_index, bool *created)
{
    int empty = -1;
    unsigned int index;

    for (index = 0; index < MELODI_ORDER_FLOW_LIMIT; index++) {
        struct melodi_order_rx_flow *flow = &melodi->order_rx[index];

        if (!flow->active && empty < 0)
            empty = index;
        if (flow->active && flow->generation == generation &&
            flow->session_epoch == session_epoch &&
            flow->source_service == source_service &&
            flow->destination_service == destination_service &&
            !memcmp(&flow->source, source, sizeof(*source))) {
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

static int melodi_order_admit_locked(
    struct melodi_device *melodi, const struct melodi_node_id *source,
    const struct melodi_wire_data *header, u64 session_epoch,
    const struct melodi_rx_meta *metadata, u8 **payload, size_t length,
    struct melodi_order_batch *batch)
{
    struct melodi_order_state next_state;
    struct melodi_order_message *message;
    struct melodi_order_rx_flow *flow;
    u32 release_marker;
    u8 release_count;
    u8 flow_index;
    bool created;
    int result;

    result = melodi_order_rx_flow_locked(
        melodi, source, header->source_service, header->destination_service,
        header->common.identity_generation, session_epoch, &flow_index,
        &created);
    if (result)
        return result;
    flow = &melodi->order_rx[flow_index];
    if (created)
        melodi_order_reset(&next_state);
    else
        next_state = flow->state;
    result = melodi_order_admit(&next_state, header->ordering_marker,
                                melodi_reliability_now(), &release_marker,
                                &release_count);
    if (result < 0)
        return result;
    if (result == MELODI_ORDER_DUPLICATE)
        return 0;
    if (length > MELODI_ORDER_BYTE_LIMIT - melodi->order_bytes)
        return -ENOSPC;
    message = melodi_order_message_empty(melodi);
    if (!message)
        return -ENOSPC;
    if (created) {
        memset(flow, 0, sizeof(*flow));
        flow->source = *source;
        flow->session_epoch = session_epoch;
        flow->generation = header->common.identity_generation;
        flow->source_service = header->source_service;
        flow->destination_service = header->destination_service;
        flow->active = true;
    }
    flow->state = next_state;
    message->source = *source;
    message->metadata = *metadata;
    message->payload = *payload;
    message->length = length;
    message->marker = header->ordering_marker;
    message->source_service = header->source_service;
    message->destination_service = header->destination_service;
    message->flow_index = flow_index;
    message->active = true;
    melodi->order_bytes += length;
    *payload = NULL;
    if (result == MELODI_ORDER_RELEASED) {
        result = melodi_order_detach_locked(
            melodi, flow_index, release_marker, release_count, batch);
        if (result) {
            melodi_order_flow_clear(melodi, flow_index);
            return result;
        }
    }
    melodi_reassembly_schedule(melodi);
    return 0;
}

static void melodi_order_deliver(struct net_device *dev,
                                 struct melodi_order_batch *batch)
{
    unsigned int index;

    for (index = 0; index < batch->count; index++) {
        struct melodi_order_message *message = &batch->messages[index];

        melodi_netlink_receive(dev, &message->source,
                               message->source_service,
                               message->destination_service,
                               message->payload, message->length,
                               &message->metadata);
        kfree_sensitive(message->payload);
        memset(message, 0, sizeof(*message));
    }
    batch->count = 0;
}

static int melodi_order_poll_locked(struct melodi_device *melodi,
                                    struct melodi_order_batch *batch)
{
    u32 release_marker;
    u8 release_count;
    unsigned int index;
    int result;

    for (index = 0; index < MELODI_ORDER_FLOW_LIMIT; index++) {
        struct melodi_order_rx_flow *flow = &melodi->order_rx[index];

        if (!flow->active)
            continue;
        result = melodi_order_poll(&flow->state, melodi_reliability_now(),
                                   &release_marker, &release_count);
        if (result < 0) {
            melodi_order_flow_clear(melodi, index);
            return result;
        }
        if (result != MELODI_ORDER_RELEASED)
            continue;
        result = melodi_order_detach_locked(
            melodi, index, release_marker, release_count, batch);
        if (result)
            melodi_order_flow_clear(melodi, index);
        return result;
    }
    return 0;
}

static void melodi_pending_clear(struct melodi_pending_message *pending)
{
    unsigned int index;

    if (!pending->allocated)
        return;
    for (index = 0; index < pending->reliability.fragment_count; index++)
        kfree_skb(pending->fragments[index]);
    memset(pending, 0, sizeof(*pending));
}

bool melodi_data_cancel_pending_locked(
    struct melodi_device *melodi,
    const struct melodi_node_id *destination, u64 message_id,
    u64 reservation_id)
{
    unsigned int index;

    for (index = 0; index < MELODI_PENDING_LIMIT; index++) {
        struct melodi_pending_message *pending = &melodi->pending[index];

        if (!pending->allocated ||
            (reservation_id && pending->reservation_id != reservation_id) ||
            (message_id &&
             pending->reliability.message_id != message_id) ||
            (destination &&
             memcmp(&pending->destination, destination,
                    sizeof(*destination))))
            continue;
        melodi_pending_clear(pending);
        return true;
    }
    return false;
}

static u64 melodi_reliability_now(void)
{
    return div_u64(ktime_get_boottime_ns(), NSEC_PER_MSEC);
}

static bool melodi_node_equal(const struct melodi_node_id *first,
                              const struct melodi_node_id *second)
{
    return !memcmp(first, second, sizeof(*first));
}

static struct melodi_discovery_target *melodi_discovery_target_find_locked(
    struct melodi_device *melodi, const struct melodi_node_id *destination,
    struct melodi_discovery_target **empty)
{
    unsigned int index;

    *empty = NULL;
    for (index = 0; index < MELODI_DISCOVERY_TARGET_LIMIT; index++) {
        struct melodi_discovery_target *target =
            &melodi->discovery_targets[index];

        if (!target->active && !*empty)
            *empty = target;
        if (target->active &&
            melodi_node_equal(&target->destination, destination))
            return target;
    }
    return NULL;
}

static bool melodi_discovery_destination_pending_locked(
    const struct melodi_device *melodi,
    const struct melodi_node_id *destination)
{
    unsigned int index;

    for (index = 0; index < MELODI_DISCOVERY_PENDING_LIMIT; index++)
        if (melodi->discovery_pending[index].active &&
            melodi_node_equal(
                &melodi->discovery_pending[index].destination,
                destination))
            return true;
    return false;
}

static void melodi_discovery_target_release_locked(
    struct melodi_device *melodi,
    const struct melodi_node_id *destination)
{
    struct melodi_discovery_target *empty;
    struct melodi_discovery_target *target;

    if (melodi_discovery_destination_pending_locked(melodi, destination))
        return;
    target = melodi_discovery_target_find_locked(melodi, destination,
                                                  &empty);
    if (target)
        memset(target, 0, sizeof(*target));
}

static void melodi_discovery_pending_clear_locked(
    struct melodi_device *melodi,
    struct melodi_discovery_pending *pending)
{
    struct melodi_node_id destination;

    if (!pending->active)
        return;
    destination = pending->destination;
    if (melodi->discovery_bytes >= pending->length)
        melodi->discovery_bytes -= pending->length;
    else
        melodi->discovery_bytes = 0;
    if (melodi->discovery_count)
        melodi->discovery_count--;
    kfree_sensitive(pending->payload);
    memset(pending, 0, sizeof(*pending));
    melodi_discovery_target_release_locked(melodi, &destination);
}

static void melodi_discovery_schedule_locked(struct melodi_device *melodi,
                                             unsigned long delay)
{
    if (melodi->discovery_count)
        mod_delayed_work(system_wq, &melodi->discovery_work, delay);
}

static int melodi_discovery_pending_admit(
    struct net_device *dev, const struct melodi_node_id *destination,
    u16 source_service, u16 destination_service, const void *payload,
    size_t length, u32 flags, u64 cookie, u32 ttl_ms,
    u32 binding_portid, u64 binding_generation, u8 priority)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_discovery_pending *pending = NULL;
    struct melodi_discovery_target *target;
    struct melodi_discovery_target *empty_target;
    u8 *copy = NULL;
    u64 now_ms = melodi_reliability_now();
    u64 expires_ms;
    unsigned int destination_count = 0;
    unsigned int index;
    bool probe = false;
    int error = 0;

    if (flags & MELODI_F_DONTWAIT)
        return -EHOSTUNREACH;
    if (length) {
        copy = kmemdup(payload, length, GFP_KERNEL);
        if (!copy)
            return -ENOMEM;
    }
    mutex_lock(&melodi->lock);
    if (!melodi->identity_ready)
        error = -ENOKEY;
    else if (!melodi->transport_ready)
        error = -ENETDOWN;
    target = melodi_discovery_target_find_locked(
        melodi, destination, &empty_target);
    if (!error && target && now_ms >= target->expires_ms)
        error = -EHOSTUNREACH;
    for (index = 0; !error &&
                    index < MELODI_DISCOVERY_PENDING_LIMIT; index++) {
        struct melodi_discovery_pending *candidate =
            &melodi->discovery_pending[index];

        if (!candidate->active && !pending)
            pending = candidate;
        if (candidate->active &&
            melodi_node_equal(&candidate->destination, destination))
            destination_count++;
    }
    if (!error && (!pending ||
        melodi->discovery_count >= MELODI_DISCOVERY_PENDING_LIMIT ||
        destination_count >= MELODI_DISCOVERY_PER_NODE_LIMIT ||
        length > MELODI_DISCOVERY_BYTE_LIMIT - melodi->discovery_bytes))
        error = -ENOBUFS;
    if (!error && !target) {
        if (!empty_target)
            error = -ENOSPC;
        else {
            target = empty_target;
            target->destination = *destination;
            target->expires_ms = now_ms +
                min_t(u32, ttl_ms, MELODI_DISCOVERY_TIMEOUT_MS);
            target->active = true;
            probe = true;
        }
    }
    if (!error) {
        expires_ms = min_t(u64, now_ms + ttl_ms, target->expires_ms);
        pending->destination = *destination;
        pending->payload = copy;
        pending->cookie = cookie;
        pending->expires_ms = expires_ms;
        pending->binding_generation = binding_generation;
        pending->binding_portid = binding_portid;
        pending->flags = flags;
        pending->length = length;
        pending->source_service = source_service;
        pending->destination_service = destination_service;
        pending->priority = priority;
        pending->active = true;
        melodi->discovery_bytes += length;
        melodi->discovery_count++;
        copy = NULL;
    }
    mutex_unlock(&melodi->lock);
    kfree_sensitive(copy);
    if (error)
        return error;
    if (probe) {
        error = melodi_discovery_probe(dev);
        if (error) {
            mutex_lock(&melodi->lock);
            melodi_discovery_pending_clear_locked(melodi, pending);
            mutex_unlock(&melodi->lock);
            return error;
        }
    }
    mutex_lock(&melodi->lock);
    melodi_discovery_schedule_locked(melodi, msecs_to_jiffies(100));
    mutex_unlock(&melodi->lock);
    return 0;
}

static bool melodi_discovery_retryable(int error)
{
    return error == -EHOSTUNREACH || error == -EAGAIN ||
           error == -ENOBUFS || error == -ENOSPC || error == -ENOMEM;
}

static void melodi_discovery_work(struct work_struct *work)
{
    struct melodi_device *melodi = container_of(
        to_delayed_work(work), struct melodi_device, discovery_work);
    struct melodi_discovery_pending *pending = NULL;
    struct melodi_peer *peer;
    u64 binding_generation = 0;
    u64 cookie = 0;
    u64 now_ms = melodi_reliability_now();
    u32 binding_portid = 0;
    u16 source_service = 0;
    u32 ttl_ms = 0;
    unsigned int index;
    int terminal = 0;
    int result;

    mutex_lock(&melodi->lock);
    for (index = 0; index < MELODI_DISCOVERY_PENDING_LIMIT; index++) {
        struct melodi_discovery_pending *candidate =
            &melodi->discovery_pending[index];

        if (!candidate->active || candidate->in_flight)
            continue;
        if (now_ms >= candidate->expires_ms) {
            binding_portid = candidate->binding_portid;
            binding_generation = candidate->binding_generation;
            source_service = candidate->source_service;
            cookie = candidate->cookie;
            terminal = -EHOSTUNREACH;
            melodi_discovery_pending_clear_locked(melodi, candidate);
            break;
        }
        peer = melodi_peer_by_node(melodi, &candidate->destination);
        if (peer && peer->session_ready && !peer->conflicted) {
            candidate->in_flight = true;
            pending = candidate;
            ttl_ms = min_t(u64, candidate->expires_ms - now_ms,
                           U32_MAX);
            break;
        }
    }
    melodi_discovery_schedule_locked(
        melodi, terminal ? 1 : msecs_to_jiffies(100));
    mutex_unlock(&melodi->lock);
    if (terminal) {
        melodi_netlink_delivery_error(
            melodi->netdev, binding_portid, binding_generation,
            source_service, cookie, terminal);
        return;
    }
    if (!pending)
        return;
    result = melodi_data_send_internal(
        melodi->netdev, &pending->destination, pending->source_service,
        pending->destination_service, pending->payload, pending->length,
        pending->flags, pending->cookie, ttl_ms, pending->binding_portid,
        pending->binding_generation, pending->priority, false, 0);
    mutex_lock(&melodi->lock);
    now_ms = melodi_reliability_now();
    if (!result) {
        melodi_discovery_pending_clear_locked(melodi, pending);
    } else if (melodi_discovery_retryable(result) &&
               now_ms < pending->expires_ms) {
        pending->in_flight = false;
    } else {
        binding_portid = pending->binding_portid;
        binding_generation = pending->binding_generation;
        source_service = pending->source_service;
        cookie = pending->cookie;
        terminal = result;
        melodi_discovery_pending_clear_locked(melodi, pending);
    }
    melodi_discovery_schedule_locked(melodi, msecs_to_jiffies(100));
    mutex_unlock(&melodi->lock);
    if (terminal)
        melodi_netlink_delivery_error(
            melodi->netdev, binding_portid, binding_generation,
            source_service, cookie, terminal);
}

static bool melodi_reliability_pending(struct melodi_device *melodi)
{
    unsigned int index;

    for (index = 0; index < MELODI_PENDING_LIMIT; index++)
        if (melodi->pending[index].allocated)
            return true;
    return false;
}

static void melodi_reliability_schedule(struct melodi_device *melodi)
{
    if (melodi_reliability_pending(melodi))
        mod_delayed_work(system_wq, &melodi->reliability_work,
                         msecs_to_jiffies(100));
}

static int melodi_pending_valid_locked(
    struct melodi_device *melodi,
    const struct melodi_pending_message *pending)
{
    struct melodi_peer *peer;
    int error;

    if (melodi_reliability_now() >= pending->expires_ms)
        return -ETIMEDOUT;
    if (!melodi->transport_ready ||
        melodi->identity_generation != pending->reliability.generation ||
        melodi->local_native_locator != pending->source_native_locator ||
        melodi->local_link_locator != pending->source_link_locator)
        return -ENETDOWN;
    peer = melodi_peer_by_node(melodi, &pending->destination);
    if (!peer || !peer->session_ready || peer->conflicted)
        return -EHOSTUNREACH;
    if (peer->native_locator != pending->destination_native_locator ||
        peer->link_locator != pending->destination_link_locator ||
        peer->generation != pending->destination_generation ||
        peer->session_epoch != pending->session_epoch)
        return -EKEYREVOKED;
    error = melodi_policy_check_locked(melodi, &pending->destination);
    if (!error)
        error = melodi_policy_check_service_locked(
            melodi, pending->destination_service, false);
    return error;
}

int melodi_data_queue_valid_locked(
    struct melodi_device *melodi,
    const struct melodi_node_id *destination, u16 destination_service,
    bool broadcast, const struct melodi_tx_meta *metadata,
    u32 identity_generation, u64 session_epoch)
{
    struct melodi_peer *peer;
    int error;

    if (!melodi->identity_ready || !melodi->transport_ready ||
        melodi->identity_generation != identity_generation ||
        melodi->local_link_locator != metadata->source_locator)
        return -EKEYREVOKED;
    error = melodi_policy_check_message_locked(
        melodi, destination, destination_service, broadcast);
    if (error || broadcast)
        return error;
    peer = melodi_peer_by_node(melodi, destination);
    if (!peer || !peer->session_ready || peer->conflicted ||
        peer->link_locator != metadata->destination_locator)
        return -EHOSTUNREACH;
    return peer->session_epoch == session_epoch ? 0 : -EKEYREVOKED;
}

void melodi_data_state_changed(struct net_device *dev)
{
    struct melodi_device *melodi = netdev_priv(dev);
    u64 binding_generation;
    u64 cookie;
    u32 binding_portid;
    u16 source_service;
    unsigned int index;
    int error;

    for (;;) {
        error = 0;
        mutex_lock(&melodi->lock);
        for (index = 0; index < MELODI_PENDING_LIMIT; index++) {
            struct melodi_pending_message *pending =
                &melodi->pending[index];

            if (!pending->allocated)
                continue;
            error = melodi_pending_valid_locked(melodi, pending);
            if (!error)
                continue;
            binding_portid = pending->binding_portid;
            binding_generation = pending->binding_generation;
            source_service = pending->source_service;
            cookie = pending->cookie;
            melodi_pending_clear(pending);
            break;
        }
        if (!error)
            for (index = 0;
                 index < MELODI_DISCOVERY_PENDING_LIMIT; index++) {
                struct melodi_discovery_pending *pending =
                    &melodi->discovery_pending[index];

                if (!pending->active || pending->in_flight)
                    continue;
                error = melodi_policy_check_message_locked(
                    melodi, &pending->destination,
                    pending->destination_service, false);
                if (!error)
                    continue;
                binding_portid = pending->binding_portid;
                binding_generation = pending->binding_generation;
                source_service = pending->source_service;
                cookie = pending->cookie;
                melodi_discovery_pending_clear_locked(melodi, pending);
                break;
            }
        mutex_unlock(&melodi->lock);
        if (!error)
            return;
        melodi_netlink_delivery_error(
            dev, binding_portid, binding_generation, source_service,
            cookie, error);
    }
}

static void melodi_reliability_work(struct work_struct *work)
{
    struct melodi_device *melodi = container_of(
        to_delayed_work(work), struct melodi_device, reliability_work);
    struct net_device *dev = melodi->netdev;
    struct melodi_tx_meta metadata = {};
    struct melodi_queue_request request = {};
    struct sk_buff *frames[MELODI_FRAGMENT_LIMIT] = {};
    u64 missing = 0;
    u64 cookie = 0;
    u64 binding_generation = 0;
    u32 binding_portid = 0;
    u16 source_service = 0;
    unsigned int count = 0;
    unsigned int index;
    bool busy = melodi_core_link_busy(dev);
    int terminal = 0;
    int result;

    mutex_lock(&melodi->lock);
    for (index = 0; index < MELODI_PENDING_LIMIT; index++) {
        struct melodi_pending_message *pending = &melodi->pending[index];
        unsigned int fragment;

        if (!pending->allocated)
            continue;
        result = melodi_pending_valid_locked(melodi, pending);
        if (result) {
            terminal = result;
            cookie = pending->cookie;
            binding_portid = pending->binding_portid;
            binding_generation = pending->binding_generation;
            source_service = pending->source_service;
            melodi_pending_clear(pending);
            break;
        }
        result = melodi_reliability_poll(
            &pending->reliability, melodi_reliability_now(),
            busy || melodi_queue_message_queued(
                dev, &pending->destination, pending->reliability.message_id,
                pending->binding_portid, pending->binding_generation,
                pending->source_service),
            &missing);
        if (result < 0 && result != -ENOENT) {
            terminal = result;
            cookie = pending->cookie;
            binding_portid = pending->binding_portid;
            binding_generation = pending->binding_generation;
            source_service = pending->source_service;
            melodi_pending_clear(pending);
            break;
        }
        if (result != 1)
            continue;
        metadata.cookie = pending->cookie;
        metadata.source_locator = pending->source_link_locator;
        metadata.destination_locator = pending->destination_link_locator;
        request.ttl_ms = min_t(u64,
            pending->expires_ms - melodi_reliability_now(), U32_MAX);
        request.binding_portid = pending->binding_portid;
        request.binding_generation = pending->binding_generation;
        request.service = pending->source_service;
        request.destination = pending->destination;
        request.destination_service = pending->destination_service;
        request.identity_generation = pending->reliability.generation;
        request.source_locator = pending->source_link_locator;
        request.session_epoch = pending->session_epoch;
        request.message_id = pending->reliability.message_id;
        request.priority = pending->priority;
        request.reliable = true;
        for (fragment = 0;
             fragment < pending->reliability.fragment_count; fragment++) {
            if (!(missing & (1ULL << fragment)))
                continue;
            frames[count] = skb_clone(pending->fragments[fragment],
                                      GFP_KERNEL);
            if (frames[count])
                count++;
        }
        break;
    }
    melodi_reliability_schedule(melodi);
    mutex_unlock(&melodi->lock);
    if (count)
        result = melodi_core_send_batch(dev, frames, count, &metadata,
                                        &request);
    for (index = 0; index < count; index++)
        kfree_skb(frames[index]);
    if (terminal)
        melodi_netlink_delivery_error(dev, binding_portid,
                                      binding_generation, source_service,
                                      cookie, terminal);
}

void melodi_data_reassembly_reset_locked(struct melodi_device *melodi)
{
    unsigned int index;

    for (index = 0; index < MELODI_REASSEMBLY_LIMIT; index++)
        melodi_reassembly_clear(melodi, &melodi->reassemblies[index]);
    memset(melodi->receipts, 0, sizeof(melodi->receipts));
    melodi->reassembly_bytes = 0;
}

void melodi_data_reset_locked(struct melodi_device *melodi)
{
    unsigned int index;

    melodi_data_reassembly_reset_locked(melodi);
    melodi_data_order_reset_locked(melodi);
    for (index = 0; index < MELODI_PENDING_LIMIT; index++)
        melodi_pending_clear(&melodi->pending[index]);
    for (index = 0; index < MELODI_DISCOVERY_PENDING_LIMIT; index++)
        melodi_discovery_pending_clear_locked(
            melodi, &melodi->discovery_pending[index]);
    memset(melodi->discovery_targets, 0,
           sizeof(melodi->discovery_targets));
    melodi->discovery_bytes = 0;
    melodi->discovery_count = 0;
}

void melodi_data_fail_pending(struct net_device *dev, int error)
{
    struct melodi_device *melodi = netdev_priv(dev);
    u64 cookie;
    u64 binding_generation;
    u32 binding_portid;
    u16 source_service;
    unsigned int index;

    cancel_delayed_work_sync(&melodi->reliability_work);
    cancel_delayed_work_sync(&melodi->discovery_work);
    for (;;) {
        source_service = 0;
        mutex_lock(&melodi->lock);
        for (index = 0; index < MELODI_PENDING_LIMIT; index++)
            if (melodi->pending[index].allocated) {
                cookie = melodi->pending[index].cookie;
                binding_portid = melodi->pending[index].binding_portid;
                binding_generation =
                    melodi->pending[index].binding_generation;
                source_service = melodi->pending[index].source_service;
                melodi_pending_clear(&melodi->pending[index]);
                break;
            }
        mutex_unlock(&melodi->lock);
        if (!source_service)
            break;
        melodi_netlink_delivery_error(dev, binding_portid,
                                      binding_generation, source_service,
                                      cookie, error);
    }
    for (;;) {
        source_service = 0;
        mutex_lock(&melodi->lock);
        for (index = 0; index < MELODI_DISCOVERY_PENDING_LIMIT; index++)
            if (melodi->discovery_pending[index].active) {
                struct melodi_discovery_pending *pending =
                    &melodi->discovery_pending[index];

                cookie = pending->cookie;
                binding_portid = pending->binding_portid;
                binding_generation = pending->binding_generation;
                source_service = pending->source_service;
                melodi_discovery_pending_clear_locked(melodi, pending);
                break;
            }
        mutex_unlock(&melodi->lock);
        if (!source_service)
            break;
        melodi_netlink_delivery_error(dev, binding_portid,
                                      binding_generation, source_service,
                                      cookie, error);
    }
}

static void melodi_reassembly_schedule(struct melodi_device *melodi)
{
    unsigned long earliest = 0;
    unsigned long delay;
    unsigned long target;
    u64 now_ms = melodi_reliability_now();
    u64 remaining;
    unsigned int index;

    for (index = 0; index < MELODI_REASSEMBLY_LIMIT; index++)
        if (melodi->reassemblies[index].active &&
            (!earliest || time_before(melodi->reassemblies[index].expires,
                                      earliest)))
            earliest = melodi->reassemblies[index].expires;
    for (index = 0; index < MELODI_RECEIPT_LIMIT; index++)
        if (melodi->receipts[index].active &&
            (!earliest || time_before(melodi->receipts[index].expires,
                                      earliest)))
            earliest = melodi->receipts[index].expires;
    for (index = 0; index < MELODI_ORDER_FLOW_LIMIT; index++) {
        const struct melodi_order_state *state =
            &melodi->order_rx[index].state;

        if (!melodi->order_rx[index].active || !state->pending ||
            !state->deadline_ms)
            continue;
        remaining = state->deadline_ms > now_ms ?
                    state->deadline_ms - now_ms : 0;
        delay = remaining ? msecs_to_jiffies(remaining) : 1;
        if (!delay)
            delay = 1;
        target = jiffies + delay;
        if (!earliest || time_before(target, earliest))
            earliest = target;
    }
    if (!earliest)
        return;
    delay = time_after_eq(jiffies, earliest) ? 1 : earliest - jiffies;
    mod_delayed_work(system_wq, &melodi->reassembly_work, delay);
}

static void melodi_reassembly_expire(struct melodi_device *melodi)
{
    unsigned int index;

    for (index = 0; index < MELODI_REASSEMBLY_LIMIT; index++)
        if (melodi->reassemblies[index].active &&
            time_after_eq(jiffies, melodi->reassemblies[index].expires))
            melodi_reassembly_clear(melodi,
                                    &melodi->reassemblies[index]);
    for (index = 0; index < MELODI_RECEIPT_LIMIT; index++)
        if (melodi->receipts[index].active &&
            time_after_eq(jiffies, melodi->receipts[index].expires))
            memset(&melodi->receipts[index], 0,
                   sizeof(melodi->receipts[index]));
}

static void melodi_reassembly_work(struct work_struct *work)
{
    struct melodi_device *melodi = container_of(
        to_delayed_work(work), struct melodi_device, reassembly_work);
    struct melodi_order_batch *batch;

    batch = kzalloc(sizeof(*batch), GFP_KERNEL);
    if (!batch) {
        mod_delayed_work(system_wq, &melodi->reassembly_work,
                         msecs_to_jiffies(100));
        return;
    }

    mutex_lock(&melodi->lock);
    melodi_reassembly_expire(melodi);
    melodi_order_poll_locked(melodi, batch);
    melodi_reassembly_schedule(melodi);
    mutex_unlock(&melodi->lock);
    melodi_order_deliver(melodi->netdev, batch);
    kfree(batch);
}

void melodi_data_init(struct melodi_device *melodi)
{
    INIT_DELAYED_WORK(&melodi->reassembly_work, melodi_reassembly_work);
    INIT_DELAYED_WORK(&melodi->reliability_work, melodi_reliability_work);
    INIT_DELAYED_WORK(&melodi->discovery_work, melodi_discovery_work);
}

void melodi_data_stop(struct melodi_device *melodi)
{
    cancel_delayed_work_sync(&melodi->reassembly_work);
    cancel_delayed_work_sync(&melodi->reliability_work);
    cancel_delayed_work_sync(&melodi->discovery_work);
    mutex_lock(&melodi->lock);
    melodi_data_reset_locked(melodi);
    mutex_unlock(&melodi->lock);
}

static struct melodi_reassembly *
melodi_reassembly_find(struct melodi_device *melodi,
                       const struct melodi_node_id *source, u32 generation,
                       u64 session_epoch, u64 message_id)
{
    struct melodi_reassembly *empty = NULL;
    unsigned int index;

    for (index = 0; index < MELODI_REASSEMBLY_LIMIT; index++) {
        struct melodi_reassembly *entry = &melodi->reassemblies[index];

        if (!entry->active && !empty)
            empty = entry;
        if (entry->active && entry->generation == generation &&
            entry->session_epoch == session_epoch &&
            entry->message_id == message_id &&
            !memcmp(&entry->source, source, sizeof(*source)))
            return entry;
    }
    return empty;
}

static bool melodi_reassembly_consistent(
    const struct melodi_reassembly *entry,
    const struct melodi_wire_data *header)
{
    return entry->logical_length == header->logical_length &&
           entry->source_service == header->source_service &&
           entry->destination_service == header->destination_service &&
           entry->fragment_count == header->fragment_count &&
           entry->flags ==
               (header->common.flags & ~MELODI_WIRE_F_FINAL) &&
           entry->delivery_mode == header->delivery_mode &&
           entry->priority == header->priority &&
           entry->ordering_marker == header->ordering_marker;
}

static int melodi_reassembly_add(struct melodi_device *melodi,
                                 const struct melodi_node_id *source,
                                 const struct melodi_wire_data *header,
                                 u64 session_epoch,
                                 const struct melodi_rx_meta *metadata,
                                 u8 **fragment,
                                 struct melodi_node_id *complete_source,
                                 u16 *complete_source_service,
                                 u16 *complete_destination_service,
                                 struct melodi_rx_meta *complete_metadata,
                                 u8 **complete, size_t *complete_length,
                                 u64 *received_bitmap)
{
    struct melodi_reassembly *entry;
    u64 expected;
    size_t offset;
    unsigned int index;

    melodi_reassembly_expire(melodi);
    entry = melodi_reassembly_find(melodi, source,
                                   header->common.identity_generation,
                                   session_epoch,
                                   header->common.message_id);
    if (!entry)
        return -ENOSPC;
    if (!entry->active) {
        memset(entry, 0, sizeof(*entry));
        entry->source = *source;
        entry->metadata = *metadata;
        entry->message_id = header->common.message_id;
        entry->session_epoch = session_epoch;
        entry->expires = jiffies +
                         msecs_to_jiffies(MELODI_REASSEMBLY_TIMEOUT_MS);
        entry->generation = header->common.identity_generation;
        entry->logical_length = header->logical_length;
        entry->ordering_marker = header->ordering_marker;
        entry->source_service = header->source_service;
        entry->destination_service = header->destination_service;
        entry->fragment_count = header->fragment_count;
        entry->flags = header->common.flags & ~MELODI_WIRE_F_FINAL;
        entry->delivery_mode = header->delivery_mode;
        entry->priority = header->priority;
        entry->active = true;
    } else if (!melodi_reassembly_consistent(entry, header)) {
        melodi_reassembly_clear(melodi, entry);
        return -EPROTO;
    }
    if (entry->received & (1ULL << header->fragment_index))
        return -EALREADY;
    if (header->common.payload_length >
        MELODI_REASSEMBLY_BYTE_LIMIT - melodi->reassembly_bytes)
        return -ENOSPC;
    entry->fragments[header->fragment_index].data = *fragment;
    entry->fragments[header->fragment_index].length =
        header->common.payload_length;
    *fragment = NULL;
    entry->received |= 1ULL << header->fragment_index;
    *received_bitmap = entry->received;
    entry->received_length += header->common.payload_length;
    melodi->reassembly_bytes += header->common.payload_length;
    melodi_reassembly_schedule(melodi);
    expected = entry->fragment_count == 64 ? U64_MAX :
               (1ULL << entry->fragment_count) - 1;
    if (entry->received != expected)
        return 0;
    if (entry->received_length != entry->logical_length) {
        melodi_reassembly_clear(melodi, entry);
        return -EPROTO;
    }
    *complete = kmalloc(max_t(size_t, entry->logical_length, 1), GFP_KERNEL);
    if (!*complete) {
        melodi_reassembly_clear(melodi, entry);
        return -ENOMEM;
    }
    offset = 0;
    for (index = 0; index < entry->fragment_count; index++) {
        memcpy(*complete + offset, entry->fragments[index].data,
               entry->fragments[index].length);
        offset += entry->fragments[index].length;
    }
    *complete_source = entry->source;
    *complete_source_service = entry->source_service;
    *complete_destination_service = entry->destination_service;
    *complete_metadata = entry->metadata;
    *complete_length = entry->logical_length;
    melodi_reassembly_clear(melodi, entry);
    return 1;
}

static u16 melodi_data_wire_flags(u32 flags)
{
    u16 wire_flags = MELODI_WIRE_F_ENCRYPTED;

    if (flags & (MELODI_F_RELIABLE | MELODI_F_ORDERED))
        wire_flags |= MELODI_WIRE_F_RELIABLE;
    if (flags & MELODI_F_ORDERED)
        wire_flags |= MELODI_WIRE_F_ORDERED;
    return wire_flags;
}

static int melodi_pending_admit_locked(
    struct melodi_device *melodi, const struct melodi_node_id *destination,
    const struct melodi_tx_meta *metadata, u16 source_service,
    u16 destination_service,
    u32 source_native_locator, u32 destination_native_locator,
    u32 generation,
    u32 destination_generation, u64 session_epoch,
    u64 message_id, u16 fragment_count, u32 ttl_ms, u32 pace_ms,
    u32 binding_portid,
    u64 binding_generation, u8 priority, struct sk_buff **frames,
    struct net_device *dev, u64 reservation)
{
    struct melodi_pending_message *pending = NULL;
    u64 now_ms = melodi_reliability_now();
    unsigned int index;
    int error;

    for (index = 0; index < MELODI_PENDING_LIMIT; index++)
        if (!melodi->pending[index].allocated) {
            pending = &melodi->pending[index];
            break;
        }
    if (!pending)
        return -ENOSPC;
    if (reservation) {
        error = melodi_queue_reservation_pending(dev, reservation);
        if (error)
            return error;
    }
    if (now_ms > U64_MAX - ttl_ms)
        return -EOVERFLOW;
    error = melodi_reliability_start(&pending->reliability, message_id,
                                     generation, fragment_count, now_ms,
                                     pace_ms, ttl_ms);
    if (error)
        return error;
    pending->destination = *destination;
    pending->reservation_id = reservation;
    pending->cookie = metadata->cookie;
    pending->expires_ms = now_ms + ttl_ms;
    pending->session_epoch = session_epoch;
    pending->source_native_locator = source_native_locator;
    pending->destination_native_locator = destination_native_locator;
    pending->source_link_locator = metadata->source_locator;
    pending->destination_link_locator = metadata->destination_locator;
    pending->destination_generation = destination_generation;
    pending->source_service = source_service;
    pending->destination_service = destination_service;
    pending->binding_portid = binding_portid;
    pending->binding_generation = binding_generation;
    pending->priority = priority;
    pending->allocated = true;
    for (index = 0; index < fragment_count; index++) {
        pending->fragments[index] = frames[index];
        frames[index] = NULL;
    }
    melodi_reliability_schedule(melodi);
    return 0;
}

static int melodi_data_sign_broadcast(
    struct net_device *dev, struct sk_buff *skb,
    struct melodi_wire_data *header, const u8 *payload, size_t payload_length)
{
    u8 signature[MELODI_WIRE_SIGNATURE_SIZE] = {};
    u8 *signing;
    u8 *frame;
    size_t frame_length;
    int error;

    signing = kmalloc(MELODI_WIRE_BROADCAST_AUTH_SIZE + payload_length,
                      GFP_KERNEL);
    if (!signing)
        return -ENOMEM;
    frame = skb_put(skb, MELODI_WIRE_DATA_SIZE +
                         MELODI_WIRE_BROADCAST_OVERHEAD + payload_length);
    error = melodi_wire_encode_broadcast_data(
        frame, skb->len, header, signature, payload, payload_length,
        &frame_length);
    if (!error) {
        memcpy(signing, frame, MELODI_WIRE_BROADCAST_AUTH_SIZE);
        if (payload_length)
            memcpy(signing + MELODI_WIRE_BROADCAST_AUTH_SIZE, payload,
                   payload_length);
        error = melodi_identity_sign(
            dev, signing,
            MELODI_WIRE_BROADCAST_AUTH_SIZE + payload_length, signature);
    }
    if (!error) {
        memcpy(frame + 60, signature, MELODI_WIRE_TAG_SIZE);
        memcpy(frame + MELODI_WIRE_DATA_SIZE,
               signature + MELODI_WIRE_TAG_SIZE,
               MELODI_WIRE_BROADCAST_SIGNATURE_SUFFIX_SIZE);
    }
    memzero_explicit(signature, sizeof(signature));
    kfree_sensitive(signing);
    return error;
}

static int melodi_data_send_broadcast(
    struct net_device *dev, u16 source_service, u16 destination_service,
    const void *payload, size_t length, u64 cookie, u32 ttl_ms,
    u32 binding_portid, u64 binding_generation, u8 priority,
    u64 reservation)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_queue_request request = {
        .ttl_ms = ttl_ms,
        .binding_portid = binding_portid,
        .binding_generation = binding_generation,
        .service = source_service,
        .destination_service = destination_service,
        .priority = priority,
        .broadcast = true,
    };
    struct melodi_tx_meta metadata = { .cookie = cookie };
    struct melodi_frame_batch *batch;
    struct melodi_wire_data header = {};
    const u8 empty = 0;
    const u8 *bytes = payload;
    u64 base_counter;
    size_t fragment_length;
    size_t offset = 0;
    u32 frame_mtu;
    u32 payload_mtu;
    u16 fragment_count;
    u16 index;
    int error = 0;

    if (length > MELODI_BROADCAST_MTU)
        return -EMSGSIZE;
    frame_mtu = melodi_core_frame_mtu(dev);
    if (frame_mtu < MELODI_WIRE_DATA_SIZE +
                        MELODI_WIRE_BROADCAST_OVERHEAD ||
        (length && frame_mtu == MELODI_WIRE_DATA_SIZE +
                                 MELODI_WIRE_BROADCAST_OVERHEAD))
        return -EMSGSIZE;
    payload_mtu = frame_mtu - MELODI_WIRE_DATA_SIZE -
                  MELODI_WIRE_BROADCAST_OVERHEAD;
    fragment_count = length ? DIV_ROUND_UP(length, payload_mtu) : 1;
    if (fragment_count > MELODI_FRAGMENT_LIMIT)
        return -EMSGSIZE;
    batch = kzalloc(sizeof(*batch), GFP_KERNEL);
    if (!batch)
        return -ENOMEM;
    mutex_lock(&melodi->lock);
    if (!melodi->identity_ready || !melodi->transport_ready ||
        melodi->transmit_counter > U64_MAX - fragment_count) {
        error = !melodi->identity_ready ? -ENOKEY :
                (!melodi->transport_ready ? -ENETDOWN : -EOVERFLOW);
        goto unlock;
    }
    error = melodi_policy_check_service_locked(
        melodi, destination_service, true);
    if (error)
        goto unlock;
    base_counter = melodi->transmit_counter + 1;
    melodi->transmit_counter += fragment_count;
    header.common.flags = MELODI_WIRE_F_BROADCAST;
    header.common.source_native_locator = melodi->local_native_locator;
    header.common.destination_native_locator =
        MELODI_NATIVE_LOCATOR_BROADCAST;
    header.common.identity_generation = melodi->identity_generation;
    do {
        header.common.message_id = get_random_u64();
    } while (!header.common.message_id);
    header.destination_service = destination_service;
    header.source_service = source_service;
    header.fragment_count = fragment_count;
    header.logical_length = length;
    header.delivery_mode = MELODI_DELIVERY_UNRELIABLE;
    header.priority = priority;
    metadata.source_locator = melodi->local_link_locator;
    metadata.destination_locator = MELODI_LINK_LOCATOR_BROADCAST;
    request.identity_generation = melodi->identity_generation;
    request.source_locator = melodi->local_link_locator;
unlock:
    mutex_unlock(&melodi->lock);
    if (error)
        goto free;
    for (index = 0; index < fragment_count; index++) {
        fragment_length = min_t(size_t, payload_mtu, length - offset);
        header.fragment_index = index;
        header.common.counter = base_counter + index;
        if (index + 1 == fragment_count)
            header.common.flags |= MELODI_WIRE_F_FINAL;
        else
            header.common.flags &= ~MELODI_WIRE_F_FINAL;
        batch->outgoing[index] = alloc_skb(
            MELODI_WIRE_DATA_SIZE + MELODI_WIRE_BROADCAST_OVERHEAD +
                fragment_length,
            GFP_KERNEL);
        if (!batch->outgoing[index]) {
            error = -ENOMEM;
            goto free;
        }
        error = melodi_data_sign_broadcast(
            dev, batch->outgoing[index], &header,
            fragment_length ? bytes + offset : &empty, fragment_length);
        if (error)
            goto free;
        offset += fragment_length;
    }
    if (reservation)
        error = melodi_core_send_batch_reserved(
            dev, batch->outgoing, fragment_count, &metadata, &request,
            reservation);
    else
        error = melodi_core_send_batch(dev, batch->outgoing, fragment_count,
                                       &metadata, &request);
    if (!error)
        atomic64_inc(&melodi->broadcast_tx);
free:
    for (index = 0; index < fragment_count; index++)
        kfree_skb(batch->outgoing[index]);
    kfree(batch);
    return error;
}

int melodi_data_admit(struct net_device *dev,
                      const struct melodi_node_id *destination,
                      u16 source_service, u16 destination_service,
                      size_t length, u32 flags, u64 cookie, u32 ttl_ms,
                      u32 binding_portid, u64 binding_generation, u8 priority,
                      u64 *reservation)
{
    struct melodi_device *melodi;
    struct melodi_queue_request request = {
        .ttl_ms = ttl_ms,
        .binding_portid = binding_portid,
        .binding_generation = binding_generation,
        .service = source_service,
        .destination_service = destination_service,
        .priority = priority,
        .broadcast = flags & MELODI_F_BROADCAST,
        .reliable = flags & (MELODI_F_RELIABLE | MELODI_F_ORDERED),
    };
    struct melodi_peer *peer;
    u32 frame_mtu;
    u32 overhead;
    u32 payload_mtu;
    u32 bytes;
    u32 locator = MELODI_NATIVE_LOCATOR_INVALID;
    u16 active_pending = 0;
    u16 fragment_count;
    unsigned int index;
    bool broadcast = flags & MELODI_F_BROADCAST;
    bool reliable = flags & (MELODI_F_RELIABLE | MELODI_F_ORDERED);
    int error = 0;

    if (!dev || !reservation || length > MELODI_MESSAGE_MTU ||
        (flags & ~MELODI_F_ALL) || !ttl_ms ||
        ttl_ms > MELODI_TTL_DEFAULT_MS || priority > MELODI_PRIORITY_MAX ||
        source_service == MELODI_SERVICE_CONTROL ||
        destination_service == MELODI_SERVICE_CONTROL ||
        (broadcast == !!destination))
        return -EINVAL;
    melodi = netdev_priv(dev);
    if (destination && !melodi_node_id_valid(destination))
        return -EINVAL;
    if (destination)
        request.destination = *destination;
    if (broadcast && (reliable || length > MELODI_BROADCAST_MTU ||
                      source_service == MELODI_SERVICE_ECHO ||
                      destination_service == MELODI_SERVICE_ECHO))
        return reliable ? -EOPNOTSUPP : -EINVAL;
    if (!broadcast && destination_service == MELODI_SERVICE_ECHO && reliable)
        return -EOPNOTSUPP;
    if (!netif_running(dev) || !netif_carrier_ok(dev))
        return -ENETDOWN;
    frame_mtu = melodi_core_frame_mtu(dev);
    overhead = MELODI_WIRE_DATA_SIZE +
               (broadcast ? MELODI_WIRE_BROADCAST_OVERHEAD : 0);
    if (frame_mtu < overhead || (length && frame_mtu == overhead))
        return -EMSGSIZE;
    payload_mtu = frame_mtu - overhead;
    fragment_count = length ? DIV_ROUND_UP(length, payload_mtu) : 1;
    if (fragment_count > MELODI_FRAGMENT_LIMIT)
        return -EMSGSIZE;
    bytes = overhead * fragment_count + length;
    mutex_lock(&melodi->lock);
    if (!melodi->identity_ready || !melodi->transport_ready) {
        error = !melodi->identity_ready ? -ENOKEY : -ENETDOWN;
        goto unlock;
    }
    request.source_locator = melodi->local_link_locator;
    if (broadcast) {
        error = melodi_policy_check_service_locked(
            melodi, destination_service, true);
        locator = MELODI_LINK_LOCATOR_BROADCAST;
        request.identity_generation = melodi->identity_generation;
    } else {
        error = melodi_policy_check_locked(melodi, destination);
        if (!error)
            error = melodi_policy_check_service_locked(
                melodi, destination_service, false);
        peer = melodi_peer_by_node(melodi, destination);
        if (peer && peer->session_ready && !peer->conflicted) {
            locator = peer->link_locator;
            request.identity_generation = melodi->identity_generation;
            request.session_epoch = peer->session_epoch;
        } else if (flags & MELODI_F_DONTWAIT)
            error = -EHOSTUNREACH;
    }
    if (error)
        goto unlock;
    if (reliable)
        for (index = 0; index < MELODI_PENDING_LIMIT; index++)
            active_pending += melodi->pending[index].allocated;
    error = melodi_queue_reserve(
        dev, dev_net(dev), locator, &request, fragment_count, bytes, length,
        cookie, reliable, active_pending, reservation);
unlock:
    mutex_unlock(&melodi->lock);
    return error;
}

static int melodi_data_send_internal(
    struct net_device *dev, const struct melodi_node_id *destination,
    u16 source_service, u16 destination_service, const void *payload,
    size_t length, u32 flags, u64 cookie, u32 ttl_ms,
    u32 binding_portid, u64 binding_generation, u8 priority,
    bool queue_discovery, u64 reservation)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_queue_request request = {
        .ttl_ms = ttl_ms,
        .binding_portid = binding_portid,
        .binding_generation = binding_generation,
        .service = source_service,
        .destination_service = destination_service,
        .priority = priority,
        .broadcast = flags & MELODI_F_BROADCAST,
        .reliable = flags & (MELODI_F_RELIABLE | MELODI_F_ORDERED),
    };
    struct melodi_tx_meta metadata = { .cookie = cookie };
    struct melodi_frame_batch *batch = NULL;
    struct melodi_wire_data header = {};
    struct melodi_peer *peer;
    const u8 empty = 0;
    const u8 *bytes = payload;
    u8 key[32] = {};
    u8 nonce[24];
    u8 *encrypted = NULL;
    u8 *frame;
    u64 base_counter;
    u64 message_id;
    size_t frame_length;
    size_t fragment_length;
    size_t offset;
    u32 frame_mtu;
    u32 ordering_marker = 0;
    u32 pace_ms;
    u32 payload_mtu;
    u32 reserved_locator = MELODI_NATIVE_LOCATOR_INVALID;
    u16 fragment_count;
    u16 index;
    bool reliable;
    int error = 0;

    if ((!payload && length) || length > MELODI_MESSAGE_MTU ||
        (flags & ~MELODI_F_ALL) ||
        !ttl_ms || ttl_ms > MELODI_TTL_DEFAULT_MS ||
        priority > MELODI_PRIORITY_MAX ||
        source_service == MELODI_SERVICE_CONTROL ||
        destination_service == MELODI_SERVICE_CONTROL ||
        (!!(flags & MELODI_F_BROADCAST) == !!destination))
        return -EINVAL;
    if (destination && !melodi_node_id_valid(destination))
        return -EINVAL;
    if (destination)
        request.destination = *destination;
    if (flags & MELODI_F_BROADCAST) {
        if (source_service == MELODI_SERVICE_ECHO ||
            destination_service == MELODI_SERVICE_ECHO)
            return -EINVAL;
        if (flags & (MELODI_F_RELIABLE | MELODI_F_ORDERED))
            return -EOPNOTSUPP;
        return melodi_data_send_broadcast(
            dev, source_service, destination_service, payload, length, cookie,
            ttl_ms, binding_portid, binding_generation, priority,
            reservation);
    }
    if (destination_service == MELODI_SERVICE_ECHO &&
        (flags & (MELODI_F_RELIABLE | MELODI_F_ORDERED)))
        return -EOPNOTSUPP;
    if (reservation) {
        error = melodi_queue_reservation_locator(
            dev, reservation, &reserved_locator);
        if (error)
            return error;
    }
    frame_mtu = melodi_core_frame_mtu(dev);
    pace_ms = melodi_core_frame_pace_ms(dev);
    if (frame_mtu < MELODI_WIRE_DATA_SIZE ||
        (length && frame_mtu == MELODI_WIRE_DATA_SIZE))
        return -EMSGSIZE;
    payload_mtu = frame_mtu - MELODI_WIRE_DATA_SIZE;
    fragment_count = length ? DIV_ROUND_UP(length, payload_mtu) : 1;
    if (fragment_count > MELODI_FRAGMENT_LIMIT)
        return -EMSGSIZE;
    batch = kzalloc(sizeof(*batch), GFP_KERNEL);
    if (!batch)
        return -ENOMEM;
    encrypted = kmalloc(payload_mtu + MELODI_WIRE_TAG_SIZE, GFP_KERNEL);
    if (!encrypted) {
        error = -ENOMEM;
        goto free;
    }
    mutex_lock(&melodi->lock);
    peer = reserved_locator == MELODI_NATIVE_LOCATOR_INVALID && reservation ?
           NULL : melodi_peer_by_node(melodi, destination);
    if (!peer || !peer->session_ready || peer->conflicted) {
        error = -EHOSTUNREACH;
        goto unlock;
    }
    error = melodi_policy_check_locked(melodi, destination);
    if (!error)
        error = melodi_policy_check_service_locked(
            melodi, destination_service, false);
    if (error)
        goto unlock;
    if (melodi->transmit_counter > U64_MAX - fragment_count) {
        error = -EOVERFLOW;
        goto unlock;
    }
    base_counter = melodi->transmit_counter + 1;
    melodi->transmit_counter += fragment_count;
    do {
        message_id = get_random_u64();
    } while (!message_id);
    if (flags & MELODI_F_ORDERED) {
        error = melodi_order_tx_marker_locked(
            melodi, destination, source_service, destination_service,
            peer->generation, peer->session_epoch, &ordering_marker);
        if (error)
            goto unlock;
    }
    header.common.flags = melodi_data_wire_flags(flags);
    header.common.source_native_locator = melodi->local_native_locator;
    header.common.destination_native_locator = peer->native_locator;
    header.common.identity_generation = melodi->identity_generation;
    header.common.message_id = message_id;
    header.destination_service = destination_service;
    header.source_service = source_service;
    header.fragment_count = fragment_count;
    header.logical_length = length;
    header.priority = priority;
    header.delivery_mode = flags & MELODI_F_ORDERED ?
        MELODI_DELIVERY_RELIABLE_ORDERED :
        (flags & MELODI_F_RELIABLE ? MELODI_DELIVERY_RELIABLE :
                                     MELODI_DELIVERY_UNRELIABLE);
    header.ordering_marker = ordering_marker;
    reliable = flags & (MELODI_F_RELIABLE | MELODI_F_ORDERED);
    memcpy(key, peer->transmit_key, sizeof(key));
    metadata.source_locator = melodi->local_link_locator;
    metadata.destination_locator = peer->link_locator;
    request.identity_generation = melodi->identity_generation;
    request.source_locator = melodi->local_link_locator;
    request.session_epoch = peer->session_epoch;
    request.message_id = message_id;
unlock:
    mutex_unlock(&melodi->lock);
    if (error)
        goto free;
    offset = 0;
    for (index = 0; index < fragment_count; index++) {
        fragment_length = min_t(size_t, payload_mtu, length - offset);
        header.fragment_index = index;
        header.common.counter = base_counter + index;
        if (index + 1 == fragment_count)
            header.common.flags |= MELODI_WIRE_F_FINAL;
        else
            header.common.flags &= ~MELODI_WIRE_F_FINAL;
        batch->frames[index] = alloc_skb(
            MELODI_WIRE_DATA_SIZE + fragment_length, GFP_KERNEL);
        if (!batch->frames[index]) {
            error = -ENOMEM;
            goto free;
        }
        frame = skb_put(batch->frames[index],
                        MELODI_WIRE_DATA_SIZE + fragment_length);
        error = melodi_wire_encode_data(
            frame, MELODI_WIRE_DATA_SIZE + fragment_length, &header,
            fragment_length ? bytes + offset : &empty, fragment_length,
            &frame_length);
        if (error)
            goto free;
        melodi_data_nonce(nonce, header.common.source_native_locator,
                          header.common.identity_generation,
                          header.common.counter, header.common.message_id);
        xchacha20poly1305_encrypt(
            encrypted, fragment_length ? bytes + offset : &empty,
            fragment_length, frame, 60, nonce, key);
        memcpy(frame + MELODI_WIRE_DATA_SIZE, encrypted, fragment_length);
        memcpy(frame + 60, encrypted + fragment_length,
               MELODI_WIRE_TAG_SIZE);
        offset += fragment_length;
    }
    if (reliable) {
        for (index = 0; index < fragment_count; index++) {
            batch->outgoing[index] = skb_clone(batch->frames[index],
                                               GFP_KERNEL);
            if (!batch->outgoing[index]) {
                error = -ENOMEM;
                goto free;
            }
        }
        mutex_lock(&melodi->lock);
        peer = melodi_peer_by_node(melodi, destination);
        if (!peer || !peer->session_ready || peer->conflicted ||
            peer->link_locator != metadata.destination_locator ||
            melodi->local_link_locator != metadata.source_locator ||
            melodi->identity_generation != header.common.identity_generation)
            error = -EHOSTUNREACH;
        else
            error = melodi_pending_admit_locked(
                melodi, destination, &metadata, source_service,
                destination_service,
                header.common.source_native_locator,
                header.common.destination_native_locator,
                header.common.identity_generation, peer->generation,
                peer->session_epoch, message_id, fragment_count,
                ttl_ms, pace_ms, binding_portid, binding_generation, priority,
                batch->frames, dev, reservation);
        mutex_unlock(&melodi->lock);
        if (error)
            goto free;
    } else {
        for (index = 0; index < fragment_count; index++) {
            batch->outgoing[index] = batch->frames[index];
            batch->frames[index] = NULL;
        }
    }
    if (reservation)
        error = melodi_core_send_batch_reserved(
            dev, batch->outgoing, fragment_count, &metadata, &request,
            reservation);
    else
        error = melodi_core_send_batch(dev, batch->outgoing, fragment_count,
                                       &metadata, &request);
    if (error && reliable) {
        mutex_lock(&melodi->lock);
        for (index = 0; index < MELODI_PENDING_LIMIT; index++)
            if (melodi->pending[index].allocated &&
                melodi->pending[index].reliability.message_id == message_id &&
                melodi->pending[index].reliability.generation ==
                    header.common.identity_generation) {
                melodi_pending_clear(&melodi->pending[index]);
                break;
            }
        mutex_unlock(&melodi->lock);
    }
free:
    if (batch)
        for (index = 0; index < fragment_count; index++)
            kfree_skb(batch->frames[index]);
    if (batch)
        for (index = 0; index < fragment_count; index++)
            kfree_skb(batch->outgoing[index]);
    memzero_explicit(key, sizeof(key));
    kfree_sensitive(encrypted);
    kfree(batch);
    if (error == -EHOSTUNREACH && queue_discovery)
        return melodi_discovery_pending_admit(
            dev, destination, source_service, destination_service,
            payload, length, flags, cookie, ttl_ms, binding_portid,
            binding_generation, priority);
    return error;
}

int melodi_data_send(struct net_device *dev,
                     const struct melodi_node_id *destination,
                     u16 source_service, u16 destination_service,
                     const void *payload, size_t length, u32 flags,
                     u64 cookie, u32 ttl_ms, u32 binding_portid,
                     u64 binding_generation, u8 priority)
{
    return melodi_data_send_internal(
        dev, destination, source_service, destination_service, payload,
        length, flags, cookie, ttl_ms, binding_portid,
        binding_generation, priority, true, 0);
}

int melodi_data_send_reserved(struct net_device *dev,
                              const struct melodi_node_id *destination,
                              u16 source_service, u16 destination_service,
                              const void *payload, size_t length, u32 flags,
                              u64 cookie, u32 ttl_ms, u32 binding_portid,
                              u64 binding_generation, u8 priority,
                              u64 reservation)
{
    return melodi_data_send_internal(
        dev, destination, source_service, destination_service, payload,
        length, flags, cookie, ttl_ms, binding_portid,
        binding_generation, priority, true, reservation);
}

static int melodi_data_header_valid(const struct melodi_wire_data *header)
{
    u16 delivery_flags = header->common.flags &
                         (MELODI_WIRE_F_RELIABLE | MELODI_WIRE_F_ORDERED);
    bool broadcast = header->common.flags & MELODI_WIRE_F_BROADCAST;
    bool final = header->common.flags & MELODI_WIRE_F_FINAL;

    if (header->common.flags & MELODI_WIRE_F_IGNORABLE ||
        final != (header->fragment_index + 1 == header->fragment_count) ||
        header->fragment_count > MELODI_FRAGMENT_LIMIT ||
        header->common.source_native_locator ==
            MELODI_NATIVE_LOCATOR_INVALID ||
        header->common.source_native_locator ==
            MELODI_NATIVE_LOCATOR_BROADCAST ||
        !header->common.identity_generation || !header->common.message_id ||
        !header->common.counter ||
        header->source_service == MELODI_SERVICE_CONTROL ||
        header->destination_service == MELODI_SERVICE_CONTROL ||
        (header->source_service == MELODI_SERVICE_ECHO &&
         header->destination_service == MELODI_SERVICE_ECHO) ||
        (header->delivery_mode == MELODI_DELIVERY_RELIABLE_ORDERED) !=
            (header->ordering_marker != 0))
        return -EPROTO;
    if (broadcast) {
        if ((header->common.flags & ~MELODI_WIRE_F_FINAL) !=
                MELODI_WIRE_F_BROADCAST ||
            header->common.destination_native_locator !=
                MELODI_NATIVE_LOCATOR_BROADCAST ||
            header->logical_length > MELODI_BROADCAST_MTU ||
            header->common.payload_length <
                MELODI_WIRE_BROADCAST_OVERHEAD ||
            header->source_service == MELODI_SERVICE_ECHO ||
            header->destination_service == MELODI_SERVICE_ECHO ||
            header->delivery_mode != MELODI_DELIVERY_UNRELIABLE ||
            header->ordering_marker)
            return -EPROTO;
        return 0;
    }
    if (!(header->common.flags & MELODI_WIRE_F_ENCRYPTED) ||
        header->common.destination_native_locator ==
            MELODI_NATIVE_LOCATOR_INVALID ||
        header->common.destination_native_locator ==
            MELODI_NATIVE_LOCATOR_BROADCAST ||
        header->logical_length > MELODI_MESSAGE_MTU ||
        (header->destination_service == MELODI_SERVICE_ECHO &&
         header->delivery_mode != MELODI_DELIVERY_UNRELIABLE) ||
        (!header->common.payload_length &&
         (header->logical_length || header->fragment_count != 1)))
        return -EPROTO;
    if ((header->delivery_mode == MELODI_DELIVERY_UNRELIABLE &&
         delivery_flags) ||
        (header->delivery_mode == MELODI_DELIVERY_RELIABLE &&
         delivery_flags != MELODI_WIRE_F_RELIABLE) ||
        (header->delivery_mode == MELODI_DELIVERY_RELIABLE_ORDERED &&
         delivery_flags != (MELODI_WIRE_F_RELIABLE |
                            MELODI_WIRE_F_ORDERED)))
        return -EPROTO;
    return 0;
}

static int melodi_data_send_ack(struct net_device *dev,
                                const struct melodi_wire_data *data,
                                u64 bitmap, u8 status)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_wire_ack ack = {};
    struct melodi_tx_meta metadata = {};
    struct melodi_peer *peer;
    struct sk_buff *skb;
    const u8 empty = 0;
    u8 authenticated[MELODI_WIRE_TAG_SIZE];
    u8 frame[MELODI_WIRE_ACK_SIZE];
    u8 key[32] = {};
    u8 nonce[24];
    int error;

    mutex_lock(&melodi->lock);
    peer = melodi_peer_by_native_locator(
        melodi, data->common.source_native_locator);
    if (!peer || !peer->session_ready || peer->conflicted ||
        data->common.identity_generation != peer->generation) {
        error = -EHOSTUNREACH;
        goto unlock;
    }
    ack.common.flags = MELODI_WIRE_F_ENCRYPTED;
    ack.common.source_native_locator = melodi->local_native_locator;
    ack.common.destination_native_locator = peer->native_locator;
    ack.common.identity_generation = melodi->identity_generation;
    ack.common.message_id = data->common.message_id;
    error = melodi_counter_next_locked(melodi, &ack.common.counter);
    if (error)
        goto unlock;
    ack.acknowledged_generation = data->common.identity_generation;
    ack.fragment_count = data->fragment_count;
    ack.status = status;
    ack.bitmap = bitmap;
    memcpy(key, peer->transmit_key, sizeof(key));
    metadata.source_locator = melodi->local_link_locator;
    metadata.destination_locator = peer->link_locator;
unlock:
    mutex_unlock(&melodi->lock);
    if (error)
        goto wipe;
    error = melodi_wire_encode_ack(frame, &ack);
    if (error)
        goto wipe;
    melodi_data_nonce(nonce, ack.common.source_native_locator,
                      ack.common.identity_generation, ack.common.counter,
                      ack.common.message_id);
    xchacha20poly1305_encrypt(authenticated, &empty, 0, frame,
                              MELODI_WIRE_ACK_AUTH_SIZE, nonce, key);
    memcpy(frame + MELODI_WIRE_ACK_AUTH_SIZE, authenticated,
           sizeof(authenticated));
    skb = alloc_skb(sizeof(frame), GFP_KERNEL);
    if (!skb) {
        error = -ENOMEM;
        goto wipe;
    }
    skb_put_data(skb, frame, sizeof(frame));
    error = melodi_core_send(dev, skb, &metadata);
    if (error)
        kfree_skb(skb);
wipe:
    memzero_explicit(authenticated, sizeof(authenticated));
    memzero_explicit(key, sizeof(key));
    return error;
}

int melodi_data_receive_ack(struct net_device *dev, const void *frame,
                            size_t length,
                            const struct melodi_rx_meta *meta)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_wire_ack ack;
    struct melodi_pending_message *pending = NULL;
    struct melodi_peer *peer;
    struct melodi_node_id source;
    u8 authenticated[MELODI_WIRE_TAG_SIZE];
    u8 key[32] = {};
    u8 nonce[24];
    u8 output;
    u64 session_epoch;
    u64 cookie = 0;
    u64 binding_generation = 0;
    u32 binding_portid = 0;
    u16 source_service = 0;
    unsigned int index;
    int error;

    if (!meta)
        return -EINVAL;
    error = melodi_wire_decode_ack(frame, length, &ack);
    if (error)
        return error;
    mutex_lock(&melodi->lock);
    peer = melodi_peer_by_native_locator(
        melodi, ack.common.source_native_locator);
    if (!peer || !peer->session_ready || peer->conflicted ||
        ack.common.destination_native_locator !=
            melodi->local_native_locator ||
        meta->source_locator != peer->link_locator ||
        meta->destination_locator != melodi->local_link_locator ||
        ack.common.identity_generation != peer->generation) {
        error = -EKEYREJECTED;
        goto unlock;
    }
    memcpy(key, peer->receive_key, sizeof(key));
    source = peer->node_id;
    session_epoch = peer->session_epoch;
    mutex_unlock(&melodi->lock);
    memcpy(authenticated, ack.tag, sizeof(authenticated));
    melodi_data_nonce(nonce, ack.common.source_native_locator,
                      ack.common.identity_generation, ack.common.counter,
                      ack.common.message_id);
    if (!xchacha20poly1305_decrypt(
            &output, authenticated, sizeof(authenticated), frame,
            MELODI_WIRE_ACK_AUTH_SIZE, nonce, key)) {
        error = -EKEYREJECTED;
        goto wipe;
    }
    mutex_lock(&melodi->lock);
    peer = melodi_peer_by_native_locator(
        melodi, ack.common.source_native_locator);
    if (!peer || !peer->session_ready || peer->conflicted ||
        memcmp(&source, &peer->node_id, sizeof(source)) ||
        meta->source_locator != peer->link_locator ||
        meta->destination_locator != melodi->local_link_locator ||
        ack.common.identity_generation != peer->generation ||
        session_epoch != peer->session_epoch) {
        error = -EKEYREJECTED;
        goto unlock;
    }
    error = melodi_replay_mark(&peer->receive_replay,
                               ack.common.counter);
    if (error)
        goto unlock;
    melodi_peer_observe_locked(peer, meta);
    for (index = 0; index < MELODI_PENDING_LIMIT; index++) {
        struct melodi_pending_message *candidate = &melodi->pending[index];

        if (candidate->allocated &&
            candidate->reliability.message_id == ack.common.message_id &&
            candidate->reliability.generation ==
                ack.acknowledged_generation &&
            candidate->reliability.fragment_count == ack.fragment_count &&
            candidate->session_epoch == session_epoch &&
            candidate->destination_generation == peer->generation &&
            candidate->destination_native_locator ==
                peer->native_locator &&
            !memcmp(&candidate->destination, &source, sizeof(source))) {
            pending = candidate;
            break;
        }
    }
    if (!pending) {
        error = -ENOENT;
        goto unlock;
    }
    if (melodi_reliability_now() >= pending->expires_ms) {
        cookie = pending->cookie;
        binding_portid = pending->binding_portid;
        binding_generation = pending->binding_generation;
        source_service = pending->source_service;
        melodi_pending_clear(pending);
        error = -ETIMEDOUT;
        goto terminal;
    }
    error = melodi_reliability_ack(
        &pending->reliability, ack.common.message_id,
        ack.acknowledged_generation, ack.fragment_count, ack.bitmap,
        ack.status == MELODI_ACK_REJECTED);
    if (error == 1 || error == -ECONNREFUSED) {
        cookie = pending->cookie;
        binding_portid = pending->binding_portid;
        binding_generation = pending->binding_generation;
        source_service = pending->source_service;
        melodi_pending_clear(pending);
    }
terminal:
    melodi_reliability_schedule(melodi);
    mutex_unlock(&melodi->lock);
    if (error == -ECONNREFUSED || error == -ETIMEDOUT) {
        melodi_netlink_delivery_error(dev, binding_portid,
                                      binding_generation, source_service,
                                      cookie, error);
        error = 0;
    } else if (error == 1) {
        error = 0;
    }
    goto wipe;
unlock:
    mutex_unlock(&melodi->lock);
wipe:
    memzero_explicit(authenticated, sizeof(authenticated));
    memzero_explicit(key, sizeof(key));
    return error;
}

static int melodi_data_duplicate_ack_locked(
    struct melodi_device *melodi, const struct melodi_node_id *source,
    const struct melodi_wire_data *header, u64 session_epoch, u64 *bitmap,
    u8 *status)
{
    struct melodi_reassembly *reassembly;
    struct melodi_receipt *receipt;

    reassembly = melodi_reassembly_find(
        melodi, source, header->common.identity_generation,
        session_epoch,
        header->common.message_id);
    if (reassembly && reassembly->active &&
        reassembly->received & (1ULL << header->fragment_index)) {
        *bitmap = reassembly->received;
        *status = MELODI_ACK_PARTIAL;
        return 0;
    }
    receipt = melodi_receipt_find(
        melodi, source, header->common.identity_generation,
        session_epoch,
        header->common.message_id);
    if (!receipt || receipt->fragment_count != header->fragment_count)
        return -EALREADY;
    *bitmap = receipt->bitmap;
    *status = receipt->status;
    return 0;
}

static int melodi_data_broadcast_peer_locked(
    struct melodi_device *melodi, const struct melodi_wire_data *header,
    const struct melodi_node_id *expected,
    const struct melodi_rx_meta *metadata, struct melodi_peer **result)
{
    struct melodi_peer *peer;

    peer = melodi_peer_by_native_locator(
        melodi, header->common.source_native_locator);
    if (!peer || !peer->session_ready ||
        header->common.identity_generation != peer->generation ||
        !metadata || metadata->source_locator != peer->link_locator ||
        metadata->destination_locator != MELODI_LINK_LOCATOR_BROADCAST ||
        (expected && memcmp(expected, &peer->node_id, sizeof(*expected))) ||
        melodi_policy_check_locked(melodi, &peer->node_id))
        return -EKEYREJECTED;
    *result = peer;
    return 0;
}

static int melodi_data_authenticate_broadcast(
    struct net_device *dev, const void *frame, size_t length,
    struct melodi_wire_data *header, struct melodi_node_id *source,
    const struct melodi_rx_meta *metadata, u8 **plaintext,
    size_t *payload_length)
{
    struct melodi_device *melodi = netdev_priv(dev);
    u8 signature[MELODI_WIRE_SIGNATURE_SIZE] = {};
    const u8 *payload;
    struct melodi_peer *peer;
    u8 *signing = NULL;
    int error;

    error = melodi_wire_decode_broadcast_data(
        frame, length, header, signature, &payload, payload_length);
    if (error)
        goto out;
    signing = kmalloc(MELODI_WIRE_BROADCAST_AUTH_SIZE + *payload_length,
                      GFP_KERNEL);
    if (!signing) {
        error = -ENOMEM;
        goto out;
    }
    memcpy(signing, frame, MELODI_WIRE_BROADCAST_AUTH_SIZE);
    if (*payload_length)
        memcpy(signing + MELODI_WIRE_BROADCAST_AUTH_SIZE, payload,
               *payload_length);
    mutex_lock(&melodi->lock);
    error = melodi_data_broadcast_peer_locked(
        melodi, header, NULL, metadata, &peer);
    if (!error)
        *source = peer->node_id;
    mutex_unlock(&melodi->lock);
    if (error)
        goto out;
    error = melodi_identity_verify(
        source, signing,
        MELODI_WIRE_BROADCAST_AUTH_SIZE + *payload_length, signature);
    if (error)
        goto out;
    mutex_lock(&melodi->lock);
    error = melodi_data_broadcast_peer_locked(
        melodi, header, source, metadata, &peer);
    if (!error)
        error = melodi_replay_mark(&peer->receive_replay,
                                   header->common.counter);
    mutex_unlock(&melodi->lock);
    if (error)
        goto out;
    *plaintext = kmalloc(max_t(size_t, *payload_length, 1), GFP_KERNEL);
    if (!*plaintext) {
        error = -ENOMEM;
        goto out;
    }
    if (*payload_length)
        memcpy(*plaintext, payload, *payload_length);
    header->common.payload_length = *payload_length;
out:
    memzero_explicit(signature, sizeof(signature));
    kfree_sensitive(signing);
    return error;
}

int melodi_data_receive(struct net_device *dev, const void *frame,
                        size_t length, const struct melodi_rx_meta *link_meta)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_order_batch *order_batch = NULL;
    struct melodi_wire_data header;
    struct melodi_rx_meta metadata;
    struct melodi_rx_meta complete_metadata;
    const u8 *ciphertext;
    struct melodi_node_id source;
    struct melodi_node_id complete_source;
    struct melodi_peer *peer;
    u8 key[32] = {};
    u8 nonce[24];
    u8 *encrypted = NULL;
    u8 *plaintext = NULL;
    u8 *complete = NULL;
    size_t payload_length;
    size_t complete_length = 0;
    u64 received_bitmap = 0;
    u64 session_epoch;
    u16 complete_source_service = 0;
    u16 complete_destination_service = 0;
    u8 ack_status;
    bool broadcast;
    bool order_admitted = false;
    bool ordered;
    bool reliable;
    bool duplicate;
    int ack_error;
    int complete_state;
    int error;

    if (!link_meta)
        return -EINVAL;
    metadata = *link_meta;
    metadata.authenticated = false;
    error = melodi_wire_decode_data(frame, length, &header, &ciphertext);
    if (error)
        return error;
    error = melodi_data_header_valid(&header);
    if (error)
        return error;
    broadcast = header.common.flags & MELODI_WIRE_F_BROADCAST;
    ordered = header.delivery_mode == MELODI_DELIVERY_RELIABLE_ORDERED;
    reliable = header.delivery_mode != MELODI_DELIVERY_UNRELIABLE;
    if (ordered) {
        order_batch = kzalloc(sizeof(*order_batch), GFP_KERNEL);
        if (!order_batch)
            return -ENOMEM;
    }
    if (broadcast) {
        error = melodi_data_authenticate_broadcast(
            dev, frame, length, &header, &source, link_meta,
            &plaintext, &payload_length);
        if (error)
            goto free;
        metadata.authenticated = true;
        session_epoch = 0;
        mutex_lock(&melodi->lock);
        error = melodi_data_broadcast_peer_locked(
            melodi, &header, &source, link_meta, &peer);
        if (!error)
            error = melodi_policy_check_service_locked(
                melodi, header.destination_service, true);
        if (error)
            goto unlock;
        melodi_peer_observe_locked(peer, &metadata);
        goto admit;
    }
    payload_length = header.common.payload_length;
    encrypted = kmalloc(payload_length + MELODI_WIRE_TAG_SIZE, GFP_KERNEL);
    plaintext = kmalloc(max_t(size_t, payload_length, 1), GFP_KERNEL);
    if (!encrypted || !plaintext) {
        error = -ENOMEM;
        goto free;
    }
    mutex_lock(&melodi->lock);
    peer = melodi_peer_by_native_locator(
        melodi, header.common.source_native_locator);
    if (!peer || !peer->session_ready ||
        header.common.destination_native_locator !=
            melodi->local_native_locator ||
        link_meta->source_locator != peer->link_locator ||
        link_meta->destination_locator != melodi->local_link_locator ||
        header.common.identity_generation != peer->generation ||
        melodi_policy_check_locked(melodi, &peer->node_id) ||
        melodi_policy_check_service_locked(
            melodi, header.destination_service, false)) {
        error = -EKEYREJECTED;
        goto unlock;
    }
    duplicate = melodi_replay_seen(&peer->receive_replay,
                                   header.common.counter);
    memcpy(key, peer->receive_key, sizeof(key));
    source = peer->node_id;
    session_epoch = peer->session_epoch;
    mutex_unlock(&melodi->lock);
    memcpy(encrypted, ciphertext, payload_length);
    memcpy(encrypted + payload_length, header.tag, MELODI_WIRE_TAG_SIZE);
    melodi_data_nonce(nonce, header.common.source_native_locator,
                      header.common.identity_generation,
                      header.common.counter, header.common.message_id);
    if (!xchacha20poly1305_decrypt(plaintext, encrypted,
                                   payload_length + MELODI_WIRE_TAG_SIZE,
                                   frame, 60, nonce, key)) {
        error = -EKEYREJECTED;
        goto free;
    }
    metadata.authenticated = true;
    mutex_lock(&melodi->lock);
    peer = melodi_peer_by_native_locator(
        melodi, header.common.source_native_locator);
    if (!peer || !peer->session_ready ||
        header.common.identity_generation != peer->generation ||
        peer->session_epoch != session_epoch ||
        link_meta->source_locator != peer->link_locator ||
        link_meta->destination_locator != melodi->local_link_locator ||
        memcmp(&source, &peer->node_id, sizeof(source)) ||
        melodi_policy_check_locked(melodi, &peer->node_id) ||
        melodi_policy_check_service_locked(
            melodi, header.destination_service, false)) {
        error = -EKEYREJECTED;
        goto unlock;
    }
    if (duplicate) {
        melodi_peer_observe_locked(peer, &metadata);
        if (!reliable) {
            error = -EALREADY;
            goto unlock;
        }
        error = melodi_data_duplicate_ack_locked(
            melodi, &source, &header, session_epoch, &received_bitmap,
            &ack_status);
        mutex_unlock(&melodi->lock);
        if (!error)
            error = melodi_data_send_ack(dev, &header, received_bitmap,
                                         ack_status);
        goto free;
    }
    error = melodi_replay_mark(&peer->receive_replay,
                               header.common.counter);
    if (error == -EALREADY && reliable) {
        error = melodi_data_duplicate_ack_locked(
            melodi, &source, &header, session_epoch, &received_bitmap,
            &ack_status);
        mutex_unlock(&melodi->lock);
        if (!error)
            error = melodi_data_send_ack(dev, &header, received_bitmap,
                                         ack_status);
        goto free;
    }
    if (error)
        goto unlock;
    melodi_peer_observe_locked(peer, &metadata);
admit:
    if (header.fragment_count == 1) {
        received_bitmap = 1;
        complete = plaintext;
        plaintext = NULL;
        complete_source = source;
        complete_source_service = header.source_service;
        complete_destination_service = header.destination_service;
        complete_metadata = metadata;
        complete_length = payload_length;
        complete_state = 1;
    } else {
        complete_state = melodi_reassembly_add(
            melodi, &source, &header, session_epoch, &metadata, &plaintext,
            &complete_source, &complete_source_service,
            &complete_destination_service, &complete_metadata,
            &complete, &complete_length, &received_bitmap);
        if (complete_state < 0) {
            error = complete_state;
            goto unlock;
        }
    }
    if (complete_state == 1 && ordered) {
        error = melodi_order_admit_locked(
            melodi, &complete_source, &header, session_epoch,
            &complete_metadata, &complete, complete_length, order_batch);
        order_admitted = !error;
    }
    mutex_unlock(&melodi->lock);
    if (complete_state == 1 && ordered) {
        if (order_admitted)
            melodi_order_deliver(dev, order_batch);
    } else if (complete_state == 1 &&
               complete_destination_service == MELODI_SERVICE_ECHO) {
        error = melodi_data_send_internal(
            dev, &complete_source, MELODI_SERVICE_ECHO,
            complete_source_service, complete, complete_length,
            MELODI_F_AUTH_REQUIRED, 0, MELODI_TTL_DEFAULT_MS, 0, 0, 1,
            false, 0);
    } else if (complete_state == 1) {
        error = melodi_netlink_receive(
            dev, &complete_source, complete_source_service,
            complete_destination_service, complete, complete_length,
            &complete_metadata);
    } else {
        error = 0;
    }
    if (broadcast && complete_state == 1 && !error)
        atomic64_inc(&melodi->broadcast_rx);
    if (reliable) {
        if (complete_state != 1)
            ack_status = MELODI_ACK_PARTIAL;
        else if (ordered && order_admitted)
            ack_status = MELODI_ACK_COMPLETE;
        else if (error)
            ack_status = MELODI_ACK_REJECTED;
        else
            ack_status = MELODI_ACK_COMPLETE;
        if (complete_state == 1) {
            mutex_lock(&melodi->lock);
            ack_error = melodi_receipt_store(
                melodi, &complete_source,
                header.common.identity_generation,
                session_epoch,
                header.common.message_id, header.fragment_count,
                received_bitmap, ack_status);
            melodi_reassembly_schedule(melodi);
            mutex_unlock(&melodi->lock);
            if (!error && ack_error)
                error = ack_error;
        }
        ack_error = melodi_data_send_ack(dev, &header, received_bitmap,
                                         ack_status);
        if (!error)
            error = ack_error;
    }
    goto free;
unlock:
    mutex_unlock(&melodi->lock);
free:
    memzero_explicit(key, sizeof(key));
    kfree_sensitive(complete);
    kfree_sensitive(plaintext);
    kfree_sensitive(encrypted);
    kfree(order_batch);
    return error;
}
