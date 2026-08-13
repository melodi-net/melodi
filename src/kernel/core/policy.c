/* SPDX-License-Identifier: GPL-2.0-only */
#include "internal.h"

#include <linux/errno.h>
#include <linux/string.h>

static struct melodi_policy_peer *
melodi_policy_peer_locked(struct melodi_device *melodi,
                          const struct melodi_node_id *node_id, bool create)
{
    struct melodi_policy_peer *empty = NULL;
    unsigned int index;

    for (index = 0; index < MELODI_POLICY_PEER_LIMIT; index++) {
        struct melodi_policy_peer *entry = &melodi->policy_peers[index];

        if (!entry->active && !empty)
            empty = entry;
        if (entry->active &&
            !memcmp(&entry->node_id, node_id, sizeof(*node_id)))
            return entry;
    }
    return create ? empty : NULL;
}

int melodi_policy_check_locked(struct melodi_device *melodi,
                               const struct melodi_node_id *node_id)
{
    struct melodi_policy_peer *entry =
        melodi_policy_peer_locked(melodi, node_id, false);

    if (entry && entry->state == MELODI_PEER_BLOCKED)
        return -EACCES;
    if (melodi->policy_mode == MELODI_POLICY_REQUIRE_TRUST &&
        (!entry || entry->state != MELODI_PEER_TRUSTED))
        return -EACCES;
    return 0;
}

int melodi_policy_check_service_locked(struct melodi_device *melodi,
                                       u16 service, bool broadcast)
{
    unsigned int index;

    if (broadcast && !melodi->broadcast_allowed)
        return -EACCES;
    for (index = 0; index < MELODI_POLICY_SERVICE_LIMIT; index++)
        if (melodi->policy_services[index].active &&
            melodi->policy_services[index].service == service)
            return melodi->policy_services[index].action ==
                   MELODI_POLICY_SERVICE_DENY ? -EACCES : 0;
    return 0;
}

int melodi_policy_check_message_locked(
    struct melodi_device *melodi,
    const struct melodi_node_id *destination, u16 destination_service,
    bool broadcast)
{
    int error = 0;

    if (!broadcast)
        error = melodi_policy_check_locked(melodi, destination);
    if (!error)
        error = melodi_policy_check_service_locked(
            melodi, destination_service, broadcast);
    return error;
}

static void melodi_policy_state_changed(struct net_device *dev)
{
    melodi_queue_state_changed(dev);
    melodi_data_state_changed(dev);
}

enum melodi_peer_state
melodi_policy_peer_state_locked(struct melodi_device *melodi,
                                const struct melodi_peer *peer)
{
    struct melodi_policy_peer *entry =
        melodi_policy_peer_locked(melodi, &peer->node_id, false);

    if (entry && entry->state == MELODI_PEER_BLOCKED)
        return MELODI_PEER_BLOCKED;
    if (peer->conflicted)
        return MELODI_PEER_CONFLICTED;
    if (!peer->session_ready)
        return peer->handshake_pending ? MELODI_PEER_CHALLENGED :
                                         MELODI_PEER_OBSERVED;
    return entry && entry->state == MELODI_PEER_TRUSTED ?
           MELODI_PEER_TRUSTED : MELODI_PEER_AUTHENTICATED;
}

enum melodi_peer_policy
melodi_policy_peer_policy_locked(struct melodi_device *melodi,
                                 const struct melodi_peer *peer)
{
    struct melodi_policy_peer *entry =
        melodi_policy_peer_locked(melodi, &peer->node_id, false);

    if (!entry)
        return MELODI_PEER_POLICY_DEFAULT;
    return entry->state == MELODI_PEER_BLOCKED ?
           MELODI_PEER_POLICY_BLOCKED : MELODI_PEER_POLICY_TRUSTED;
}

int melodi_policy_set_peer(struct net_device *dev,
                           const struct melodi_node_id *node_id,
                           enum melodi_peer_state state)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_policy_peer *entry;
    unsigned int index;

    if (!melodi_node_id_valid(node_id) ||
        (state != MELODI_PEER_TRUSTED && state != MELODI_PEER_BLOCKED))
        return -EINVAL;
    mutex_lock(&melodi->lock);
    entry = melodi_policy_peer_locked(melodi, node_id, true);
    if (!entry) {
        mutex_unlock(&melodi->lock);
        return -ENOSPC;
    }
    entry->node_id = *node_id;
    entry->state = state;
    entry->active = true;
    if (state == MELODI_PEER_BLOCKED)
        for (index = 0; index < MELODI_PEER_LIMIT; index++)
            if (melodi->peers[index].authenticated &&
                !memcmp(&melodi->peers[index].node_id, node_id,
                        sizeof(*node_id))) {
                melodi_peer_session_reset_locked(melodi,
                                                 &melodi->peers[index]);
                break;
            }
    mutex_unlock(&melodi->lock);
    melodi_policy_state_changed(dev);
    return 0;
}

int melodi_policy_clear_peer(struct net_device *dev,
                             const struct melodi_node_id *node_id)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_policy_peer *entry;

    if (!melodi_node_id_valid(node_id))
        return -EINVAL;
    mutex_lock(&melodi->lock);
    entry = melodi_policy_peer_locked(melodi, node_id, false);
    if (entry)
        memset(entry, 0, sizeof(*entry));
    mutex_unlock(&melodi->lock);
    if (entry)
        melodi_policy_state_changed(dev);
    return entry ? 0 : -ENOENT;
}

int melodi_policy_set_service(struct net_device *dev, u16 service,
                              enum melodi_policy_action action)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_policy_service *entry = NULL;
    struct melodi_policy_service *empty = NULL;
    unsigned int index;
    int error = 0;

    if (service == MELODI_SERVICE_CONTROL ||
        action < MELODI_POLICY_SERVICE_ALLOW ||
        action > MELODI_POLICY_SERVICE_CLEAR)
        return -EINVAL;
    mutex_lock(&melodi->lock);
    for (index = 0; index < MELODI_POLICY_SERVICE_LIMIT; index++) {
        struct melodi_policy_service *candidate =
            &melodi->policy_services[index];

        if (!candidate->active && !empty)
            empty = candidate;
        if (candidate->active && candidate->service == service) {
            entry = candidate;
            break;
        }
    }
    if (action == MELODI_POLICY_SERVICE_CLEAR) {
        if (entry)
            memset(entry, 0, sizeof(*entry));
        else
            error = -ENOENT;
    } else {
        if (!entry)
            entry = empty;
        if (!entry)
            error = -ENOSPC;
        else {
            entry->service = service;
            entry->action = action;
            entry->active = true;
        }
    }
    mutex_unlock(&melodi->lock);
    if (!error)
        melodi_policy_state_changed(dev);
    return error;
}

int melodi_policy_set_broadcast(struct net_device *dev, bool allowed)
{
    struct melodi_device *melodi = netdev_priv(dev);

    mutex_lock(&melodi->lock);
    melodi->broadcast_allowed = allowed;
    mutex_unlock(&melodi->lock);
    melodi_policy_state_changed(dev);
    return 0;
}

int melodi_policy_set_mode(struct net_device *dev,
                           enum melodi_policy_mode mode)
{
    struct melodi_device *melodi = netdev_priv(dev);

    if (mode < MELODI_POLICY_ALLOW_AUTHENTICATED ||
        mode > MELODI_POLICY_REQUIRE_TRUST)
        return -EINVAL;
    mutex_lock(&melodi->lock);
    melodi->policy_mode = mode;
    mutex_unlock(&melodi->lock);
    melodi_policy_state_changed(dev);
    return 0;
}

int melodi_policy_reset(struct net_device *dev)
{
    struct melodi_device *melodi = netdev_priv(dev);

    mutex_lock(&melodi->lock);
    memset(melodi->policy_peers, 0, sizeof(melodi->policy_peers));
    memset(melodi->policy_services, 0, sizeof(melodi->policy_services));
    melodi->policy_mode = MELODI_POLICY_ALLOW_AUTHENTICATED;
    melodi->broadcast_allowed = true;
    mutex_unlock(&melodi->lock);
    return 0;
}

int melodi_policy_reverify_peer(struct net_device *dev,
                                const struct melodi_node_id *node_id)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_peer *peer = NULL;
    unsigned int index;

    if (!melodi_node_id_valid(node_id))
        return -EINVAL;
    mutex_lock(&melodi->lock);
    for (index = 0; index < MELODI_PEER_LIMIT; index++)
        if (melodi->peers[index].authenticated &&
            !memcmp(&melodi->peers[index].node_id, node_id,
                    sizeof(*node_id))) {
            peer = &melodi->peers[index];
            break;
    }
    if (peer) {
        melodi_peer_session_reset_locked(melodi, peer);
    }
    mutex_unlock(&melodi->lock);
    if (!peer)
        return -ENOENT;
    melodi_policy_state_changed(dev);
    return melodi_discovery_announce(dev);
}
