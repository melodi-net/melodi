/* SPDX-License-Identifier: GPL-2.0-only */
#include "internal.h"

#include "wire.h"

#include <crypto/blake2s.h>
#include <crypto/curve25519.h>
#include <linux/errno.h>
#include <linux/ktime.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/string.h>

static struct melodi_peer *melodi_peer_slot(struct melodi_device *melodi,
                                            const struct melodi_node_id *node_id)
{
    struct melodi_peer *empty = NULL;
    unsigned int index;

    for (index = 0; index < MELODI_PEER_LIMIT; index++) {
        if (!melodi->peers[index].authenticated && !empty)
            empty = &melodi->peers[index];
        if (melodi->peers[index].authenticated &&
            !memcmp(&melodi->peers[index].node_id, node_id,
                    sizeof(*node_id)))
            return &melodi->peers[index];
    }
    return empty;
}

static void melodi_peer_session_advance(struct melodi_peer *peer)
{
    peer->session_epoch++;
    if (!peer->session_epoch)
        peer->session_epoch++;
}

void melodi_peer_observe_locked(struct melodi_peer *peer,
                                const struct melodi_rx_meta *meta)
{
    if (!peer || !meta)
        return;
    peer->last_seen_ns = meta->timestamp_ns ? meta->timestamp_ns :
                                              ktime_get_ns();
    peer->rssi = meta->rssi;
    peer->snr = meta->snr;
    peer->hops = meta->hops;
}

void melodi_peer_session_reset_locked(struct melodi_device *melodi,
                                      struct melodi_peer *peer)
{
    melodi_data_peer_reset_locked(melodi, &peer->node_id);
    memzero_explicit(peer->transmit_key, sizeof(peer->transmit_key));
    memzero_explicit(peer->receive_key, sizeof(peer->receive_key));
    memzero_explicit(peer->ephemeral_private,
                     sizeof(peer->ephemeral_private));
    melodi_replay_reset(&peer->receive_replay);
    peer->session_ready = false;
    peer->handshake_pending = false;
    melodi_peer_session_advance(peer);
}

static void melodi_peer_expiry_schedule_locked(struct melodi_device *melodi)
{
    unsigned long earliest = 0;
    unsigned long delay;
    unsigned int index;

    for (index = 0; index < MELODI_PEER_LIMIT; index++)
        if (melodi->peers[index].authenticated &&
            (!earliest || time_before(melodi->peers[index].expires,
                                      earliest)))
            earliest = melodi->peers[index].expires;
    if (!earliest)
        return;
    delay = time_after_eq(jiffies, earliest) ? 1 : earliest - jiffies;
    mod_delayed_work(system_wq, &melodi->peer_expiry_work, delay);
}

static void melodi_conflicts_recompute_locked(struct melodi_device *melodi)
{
    unsigned int first;
    unsigned int second;

    for (first = 0; first < MELODI_PEER_LIMIT; first++)
        melodi->peers[first].conflicted =
            melodi->peers[first].authenticated &&
            melodi->peers[first].native_locator ==
                melodi->local_native_locator;
    for (first = 0; first < MELODI_PEER_LIMIT; first++) {
        if (!melodi->peers[first].authenticated)
            continue;
        for (second = first + 1; second < MELODI_PEER_LIMIT; second++) {
            if (!melodi->peers[second].authenticated ||
                melodi->peers[first].native_locator !=
                    melodi->peers[second].native_locator)
                continue;
            melodi->peers[first].conflicted = true;
            melodi->peers[second].conflicted = true;
        }
    }
}

static void melodi_peer_expiry_work(struct work_struct *work)
{
    struct melodi_device *melodi = container_of(
        to_delayed_work(work), struct melodi_device, peer_expiry_work);
    unsigned int index;

    mutex_lock(&melodi->lock);
    for (index = 0; index < MELODI_PEER_LIMIT; index++) {
        struct melodi_peer *peer = &melodi->peers[index];

        if (!peer->authenticated || time_before(jiffies, peer->expires))
            continue;
        melodi_peer_session_reset_locked(melodi, peer);
        memzero_explicit(peer, sizeof(*peer));
    }
    melodi_conflicts_recompute_locked(melodi);
    melodi_peer_expiry_schedule_locked(melodi);
    mutex_unlock(&melodi->lock);
    melodi_queue_state_changed(melodi->netdev);
    melodi_data_state_changed(melodi->netdev);
}

static void melodi_announce_schedule(struct melodi_device *melodi,
                                     unsigned int base_ms)
{
    unsigned int delay = base_ms +
        get_random_u32_below(MELODI_ANNOUNCE_JITTER_MS);

    mod_delayed_work(system_wq, &melodi->announce_work,
                     msecs_to_jiffies(delay));
}

/**
 * melodi_discovery_announce_soon - announce after a randomised delay
 * @dev: ready Melodi interface
 *
 * Repeats while no peer session exists. The delay is randomised so peers that
 * start together do not transmit in the same slot on a half-duplex link.
 */
void melodi_discovery_announce_soon(struct net_device *dev)
{
    struct melodi_device *melodi;

    if (!melodi_device_is(dev))
        return;
    melodi = netdev_priv(dev);
    melodi_announce_schedule(melodi, 0);
}

static void melodi_announce_work(struct work_struct *work)
{
    struct melodi_device *melodi = container_of(
        to_delayed_work(work), struct melodi_device, announce_work);
    struct net_device *dev = melodi->netdev;
    unsigned int established = 0;
    unsigned int index;

    if (!netif_running(dev) || !netif_carrier_ok(dev))
        return;
    mutex_lock(&melodi->lock);
    for (index = 0; index < MELODI_PEER_LIMIT; index++)
        established += melodi->peers[index].session_ready;
    mutex_unlock(&melodi->lock);
    if (established)
        return;
    melodi_discovery_announce(dev);
    melodi_announce_schedule(melodi, MELODI_ANNOUNCE_RETRY_MS);
}

void melodi_discovery_init(struct melodi_device *melodi)
{
    INIT_DELAYED_WORK(&melodi->peer_expiry_work,
                      melodi_peer_expiry_work);
    INIT_DELAYED_WORK(&melodi->announce_work, melodi_announce_work);
}

void melodi_discovery_stop(struct melodi_device *melodi)
{
    cancel_delayed_work_sync(&melodi->peer_expiry_work);
    cancel_delayed_work_sync(&melodi->announce_work);
}

void melodi_discovery_reset_locked(struct melodi_device *melodi)
{
    unsigned int index;

    for (index = 0; index < MELODI_PEER_LIMIT; index++) {
        struct melodi_peer *peer = &melodi->peers[index];

        if (peer->authenticated)
            melodi_peer_session_reset_locked(melodi, peer);
    }
    memzero_explicit(melodi->peers, sizeof(melodi->peers));
}

static int melodi_local_reassign_locked(struct melodi_device *melodi)
{
    u32 occupied[MELODI_PEER_LIMIT];
    u32 native_locator;
    u32 round;
    size_t count = 0;
    unsigned int index;
    int error;

    if (melodi->local_collision_round == U32_MAX)
        return -EOVERFLOW;
    for (index = 0; index < MELODI_PEER_LIMIT; index++)
        if (melodi->peers[index].authenticated)
            occupied[count++] = melodi->peers[index].native_locator;
    error = melodi_map_native_locator_available(
        melodi->mesh_domain, &melodi->node_id,
        melodi->local_collision_round + 1, occupied, count,
        &native_locator, &round);
    if (error)
        return error;
    melodi->local_native_locator = native_locator;
    melodi->local_collision_round = round;
    melodi->conflict_pending = true;
    for (index = 0; index < MELODI_PEER_LIMIT; index++)
        if (melodi->peers[index].authenticated)
            melodi_peer_session_reset_locked(melodi,
                                             &melodi->peers[index]);
    melodi_data_reassembly_reset_locked(melodi);
    melodi_data_order_reset_locked(melodi);
    memzero_explicit(occupied, sizeof(occupied));
    return 0;
}

static void melodi_hash_u32(struct blake2s_ctx *context, u32 value)
{
    u8 encoded[4] = { value >> 24, value >> 16, value >> 8, value };

    blake2s_update(context, encoded, sizeof(encoded));
}

static void melodi_session_key(u8 key[32], const u8 shared[32],
                               const u8 domain[32],
                               const struct melodi_node_id *initiator,
                               const struct melodi_node_id *responder,
                               u32 initiator_native_locator,
                               u32 responder_native_locator,
                               u32 initiator_round, u32 responder_round,
                               u32 initiator_generation,
                               u32 responder_generation,
                               const u8 initiator_ephemeral[32],
                               const u8 responder_ephemeral[32],
                               const u8 initiator_nonce[32],
                               const u8 responder_nonce[32], u8 direction)
{
    static const u8 label[] = "melodi-session-v1";
    struct blake2s_ctx context;

    blake2s_init_key(&context, 32, shared, 32);
    blake2s_update(&context, label, sizeof(label) - 1);
    blake2s_update(&context, domain, 32);
    blake2s_update(&context, initiator->bytes, MELODI_NODE_ID_SIZE);
    blake2s_update(&context, responder->bytes, MELODI_NODE_ID_SIZE);
    melodi_hash_u32(&context, initiator_native_locator);
    melodi_hash_u32(&context, responder_native_locator);
    melodi_hash_u32(&context, initiator_round);
    melodi_hash_u32(&context, responder_round);
    melodi_hash_u32(&context, initiator_generation);
    melodi_hash_u32(&context, responder_generation);
    blake2s_update(&context, initiator_ephemeral, 32);
    blake2s_update(&context, responder_ephemeral, 32);
    blake2s_update(&context, initiator_nonce, 32);
    blake2s_update(&context, responder_nonce, 32);
    blake2s_update(&context, &direction, sizeof(direction));
    blake2s_final(&context, key);
}

static int melodi_claim_locked(struct melodi_device *melodi,
                               const struct melodi_node_id *node_id,
                               u32 native_locator, u32 link_locator, u32 round,
                               u32 generation, u64 counter,
                               bool resolve_local,
                               bool *local_changed, bool *local_collision,
                               struct melodi_peer **result)
{
    struct melodi_peer *peer;
    u32 derived_locator;
    u32 selected_round;
    bool reset_session;
    int error;

    if (!link_locator || link_locator == MELODI_LINK_LOCATOR_BROADCAST)
        return -EPROTO;
    error = melodi_map_native_locator(
        melodi->mesh_domain, node_id, round, &derived_locator,
        &selected_round);
    if (error)
        return error;
    if (selected_round != round || derived_locator != native_locator)
        return -EPROTO;
    if (!memcmp(node_id, &melodi->node_id, sizeof(*node_id)))
        return -EALREADY;
    peer = melodi_peer_slot(melodi, node_id);
    if (!peer)
        return -ENOSPC;
    if (peer->authenticated &&
        (generation < peer->generation ||
         (generation == peer->generation &&
          counter <= peer->control_counter)))
        return -EALREADY;
    reset_session = !peer->authenticated || generation != peer->generation ||
                    native_locator != peer->native_locator ||
                    link_locator != peer->link_locator ||
                    round != peer->collision_round;
    if (!peer->authenticated)
        memset(peer, 0, sizeof(*peer));
    else if (reset_session)
        melodi_peer_session_reset_locked(melodi, peer);
    peer->node_id = *node_id;
    peer->native_locator = native_locator;
    peer->link_locator = link_locator;
    peer->collision_round = round;
    peer->generation = generation;
    peer->control_counter = counter;
    peer->authenticated = true;
    if (local_changed)
        *local_changed = false;
    if (local_collision)
        *local_collision = native_locator == melodi->local_native_locator;
    if (native_locator == melodi->local_native_locator &&
        memcmp(node_id, &melodi->node_id, sizeof(*node_id)) < 0 &&
        resolve_local) {
        error = melodi_local_reassign_locked(melodi);
        if (error) {
            melodi_conflicts_recompute_locked(melodi);
            return error;
        }
        if (local_changed)
            *local_changed = true;
    }
    melodi_conflicts_recompute_locked(melodi);
    if (result)
        *result = peer;
    if (peer->conflicted && !resolve_local)
        return -EADDRINUSE;
    return 0;
}

static int melodi_send_frame(struct net_device *dev, const void *frame,
                             size_t length, u32 source_native_locator,
                             u32 destination_native_locator)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_tx_meta metadata = {};
    struct sk_buff *skb;
    unsigned int index;
    int error;

    mutex_lock(&melodi->lock);
    if (!melodi->transport_ready ||
        source_native_locator != melodi->local_native_locator) {
        error = -ENETDOWN;
        goto unlock;
    }
    metadata.source_locator = melodi->local_link_locator;
    if (destination_native_locator == MELODI_NATIVE_LOCATOR_BROADCAST) {
        metadata.destination_locator = MELODI_LINK_LOCATOR_BROADCAST;
    } else {
        error = -EHOSTUNREACH;
        for (index = 0; index < MELODI_PEER_LIMIT; index++)
            if (melodi->peers[index].authenticated &&
                melodi->peers[index].native_locator ==
                    destination_native_locator) {
                metadata.destination_locator =
                    melodi->peers[index].link_locator;
                error = 0;
                break;
            }
        if (error)
            goto unlock;
    }
    error = 0;
unlock:
    mutex_unlock(&melodi->lock);
    if (error)
        return error;
    skb = alloc_skb(length, GFP_KERNEL);
    if (!skb)
        return -ENOMEM;
    skb_put_data(skb, frame, length);
    error = melodi_core_send(dev, skb, &metadata);
    if (error)
        kfree_skb(skb);
    return error;
}

static int melodi_send_auth(struct net_device *dev,
                            struct melodi_wire_auth *auth)
{
    u8 frame[MELODI_WIRE_AUTH_SIZE];
    int error;

    memset(auth->signature, 0, sizeof(auth->signature));
    error = melodi_wire_encode_auth(frame, auth);
    if (error)
        return error;
    error = melodi_identity_sign(dev, frame, MELODI_WIRE_AUTH_SIGNED_SIZE,
                                 auth->signature);
    if (error)
        return error;
    memcpy(frame + MELODI_WIRE_AUTH_SIGNED_SIZE, auth->signature,
           sizeof(auth->signature));
    return melodi_send_frame(dev, frame, sizeof(frame),
                             auth->common.source_native_locator,
                             auth->common.destination_native_locator);
}

static int melodi_send_challenge(struct net_device *dev,
                                 const struct melodi_wire_hello *hello)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_wire_auth auth = {};
    struct melodi_peer *peer;
    int error;

    mutex_lock(&melodi->lock);
    peer = melodi_peer_slot(melodi, &hello->node_id);
    if (!peer || !peer->authenticated || !melodi->identity_ready ||
        !melodi->transport_ready) {
        error = -ENETDOWN;
        goto unlock;
    }
    curve25519_generate_secret(peer->ephemeral_private);
    if (!curve25519_generate_public(peer->ephemeral_public,
                                    peer->ephemeral_private)) {
        error = -EKEYREJECTED;
        goto unlock;
    }
    get_random_bytes(peer->local_challenge, sizeof(peer->local_challenge));
    memcpy(peer->remote_hello_challenge, hello->challenge,
           sizeof(peer->remote_hello_challenge));
    peer->handshake_pending = true;
    auth.common.frame_class = MELODI_WIRE_CHALLENGE;
    auth.common.source_native_locator = melodi->local_native_locator;
    auth.common.destination_native_locator = peer->native_locator;
    auth.common.identity_generation = melodi->identity_generation;
    auth.common.message_id = get_random_u64();
    error = melodi_counter_next_locked(melodi, &auth.common.counter);
    if (error)
        goto unlock;
    auth.source_node_id = melodi->node_id;
    auth.destination_node_id = peer->node_id;
    memcpy(auth.ephemeral_key, peer->ephemeral_public, 32);
    memcpy(auth.challenge, peer->local_challenge, 32);
    memcpy(auth.reply_to, peer->remote_hello_challenge, 32);
    memcpy(auth.mesh_domain, melodi->mesh_domain, 32);
    auth.collision_round = melodi->local_collision_round;
unlock:
    mutex_unlock(&melodi->lock);
    return error ? error : melodi_send_auth(dev, &auth);
}

int melodi_discovery_announce(struct net_device *dev)
{
    struct melodi_wire_hello hello = {};
    struct melodi_device *melodi = netdev_priv(dev);
    u8 frame[MELODI_WIRE_HELLO_SIZE];
    bool conflict;
    u32 round;
    int error;

    mutex_lock(&melodi->lock);
    if (!melodi->identity_ready || !melodi->transport_ready) {
        error = -ENETDOWN;
        goto unlock;
    }
    hello.common.flags = MELODI_WIRE_F_BROADCAST;
    hello.common.source_native_locator = melodi->local_native_locator;
    hello.common.destination_native_locator =
        MELODI_NATIVE_LOCATOR_BROADCAST;
    hello.common.identity_generation = melodi->identity_generation;
    hello.common.message_id = get_random_u64();
    error = melodi_counter_next_locked(melodi, &hello.common.counter);
    if (error)
        goto unlock;
    hello.node_id = melodi->node_id;
    memcpy(hello.mesh_domain, melodi->mesh_domain, 32);
    hello.collision_round = melodi->local_collision_round;
    round = hello.collision_round;
    conflict = melodi->conflict_pending;
    hello.expiry_seconds = 300;
    get_random_bytes(hello.challenge, sizeof(hello.challenge));
    memcpy(melodi->previous_hello_challenge, melodi->last_hello_challenge,
           sizeof(melodi->previous_hello_challenge));
    memcpy(melodi->last_hello_challenge, hello.challenge,
           sizeof(melodi->last_hello_challenge));
unlock:
    mutex_unlock(&melodi->lock);
    if (error)
        return error;
    error = conflict ? melodi_wire_encode_conflict(frame, &hello) :
                       melodi_wire_encode_hello(frame, &hello);
    if (error)
        return error;
    error = melodi_identity_sign(dev, frame, MELODI_WIRE_HELLO_SIGNED_SIZE,
                                 hello.signature);
    if (error)
        return error;
    memcpy(frame + MELODI_WIRE_HELLO_SIGNED_SIZE, hello.signature,
           sizeof(hello.signature));
    error = melodi_send_frame(dev, frame, sizeof(frame),
                              hello.common.source_native_locator,
                              MELODI_NATIVE_LOCATOR_BROADCAST);
    if (!error && conflict) {
        mutex_lock(&melodi->lock);
        if (melodi->local_collision_round == round)
            melodi->conflict_pending = false;
        mutex_unlock(&melodi->lock);
    }
    return error;
}

int melodi_discovery_probe(struct net_device *dev)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_wire_control control = {};
    u8 frame[MELODI_WIRE_CONTROL_SIZE];
    int error;

    mutex_lock(&melodi->lock);
    if (!melodi->identity_ready || !melodi->transport_ready) {
        error = -ENETDOWN;
        goto unlock;
    }
    control.common.frame_class = MELODI_WIRE_CONTROL;
    control.common.flags = MELODI_WIRE_F_BROADCAST;
    control.common.source_native_locator = melodi->local_native_locator;
    control.common.destination_native_locator =
        MELODI_NATIVE_LOCATOR_BROADCAST;
    control.common.identity_generation = melodi->identity_generation;
    control.common.message_id = get_random_u64();
    error = melodi_counter_next_locked(melodi, &control.common.counter);
    if (error)
        goto unlock;
    control.node_id = melodi->node_id;
    memcpy(control.mesh_domain, melodi->mesh_domain,
           sizeof(control.mesh_domain));
    control.collision_round = melodi->local_collision_round;
    control.opcode = MELODI_CONTROL_PROBE;
unlock:
    mutex_unlock(&melodi->lock);
    if (error)
        return error;
    error = melodi_wire_encode_control(frame, &control);
    if (error)
        return error;
    error = melodi_identity_sign(dev, frame, MELODI_WIRE_CONTROL_SIGNED_SIZE,
                                 control.signature);
    if (error)
        return error;
    memcpy(frame + MELODI_WIRE_CONTROL_SIGNED_SIZE, control.signature,
           sizeof(control.signature));
    return melodi_send_frame(dev, frame, sizeof(frame),
                             control.common.source_native_locator,
                             MELODI_NATIVE_LOCATOR_BROADCAST);
}

/**
 * melodi_responder_locked - decide which peer answers a hello with a challenge
 * @melodi: local device state
 * @peer: authenticated remote identity
 *
 * Both peers announce independently, so both would otherwise challenge each
 * other and derive two sessions with different ephemeral keys. The identity
 * ordering is total and antisymmetric, so exactly one peer challenges and one
 * session exists per pair.
 */
static bool melodi_responder_locked(const struct melodi_device *melodi,
                                    const struct melodi_node_id *peer)
{
    return memcmp(melodi->node_id.bytes, peer->bytes,
                  MELODI_NODE_ID_SIZE) > 0;
}

static int melodi_receive_hello(struct net_device *dev, const void *frame,
                                size_t length, bool conflict,
                                const struct melodi_rx_meta *meta)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_wire_hello hello;
    struct melodi_peer *peer;
    bool conflicted = false;
    bool local_changed = false;
    bool local_collision = false;
    bool responder = false;
    bool established = false;
    int error;

    error = conflict ? melodi_wire_decode_conflict(frame, length, &hello) :
                       melodi_wire_decode_hello(frame, length, &hello);
    if (error)
        return error;
    if (!hello.expiry_seconds ||
        hello.expiry_seconds > MELODI_PEER_EXPIRY_MAX_SECONDS)
        return -EPROTO;
    error = melodi_identity_verify(&hello.node_id, frame,
                                   MELODI_WIRE_HELLO_SIGNED_SIZE,
                                   hello.signature);
    if (error)
        return error;
    mutex_lock(&melodi->lock);
    if (memcmp(hello.mesh_domain, melodi->mesh_domain, 32))
        error = -EXDEV;
    else
        error = melodi_claim_locked(melodi, &hello.node_id,
                                    hello.common.source_native_locator,
                                    meta->source_locator,
                                    hello.collision_round,
                                    hello.common.identity_generation,
                                    hello.common.counter, true,
                                    &local_changed, &local_collision, &peer);
    if (!error) {
        peer->capabilities = hello.capabilities;
        peer->expires = jiffies +
            msecs_to_jiffies(hello.expiry_seconds * 1000U);
        melodi_peer_observe_locked(peer, meta);
        conflicted = peer->conflicted;
        responder = melodi_responder_locked(melodi, &peer->node_id);
        established = peer->session_ready;
        melodi_peer_expiry_schedule_locked(melodi);
    }
    mutex_unlock(&melodi->lock);
    if (error)
        return error;
    if (local_changed) {
        melodi_link_ready(dev, false, 0);
        melodi_data_fail_pending(dev, -EADDRINUSE);
        return melodi_transport_configure(dev);
    }
    if (conflicted)
        return local_collision && netif_running(dev) && netif_carrier_ok(dev) ?
               melodi_discovery_announce(dev) : 0;
    if (!netif_running(dev) || !netif_carrier_ok(dev))
        return 0;
    if (established)
        return 0;
    if (responder)
        return melodi_send_challenge(dev, &hello);
    melodi_discovery_announce_soon(dev);
    return 0;
}

static int melodi_auth_validate(struct melodi_device *melodi,
                                const struct melodi_wire_auth *auth,
                                const struct melodi_rx_meta *meta,
                                struct melodi_peer **peer)
{
    struct melodi_peer *known = NULL;
    unsigned int index;

    if (!meta || memcmp(auth->mesh_domain, melodi->mesh_domain, 32) ||
        memcmp(&auth->destination_node_id, &melodi->node_id,
               sizeof(melodi->node_id)) ||
        auth->common.destination_native_locator !=
            melodi->local_native_locator ||
        meta->destination_locator != melodi->local_link_locator)
        return -EPROTO;
    for (index = 0; index < MELODI_PEER_LIMIT; index++)
        if (melodi->peers[index].authenticated &&
            !memcmp(&melodi->peers[index].node_id,
                    &auth->source_node_id, sizeof(auth->source_node_id))) {
            known = &melodi->peers[index];
            break;
        }
    if (!known)
        return -ENOENT;
    if (known->link_locator != meta->source_locator)
        return -EHOSTUNREACH;
    return melodi_claim_locked(melodi, &auth->source_node_id,
                               auth->common.source_native_locator,
                               meta->source_locator,
                               auth->collision_round,
                               auth->common.identity_generation,
                               auth->common.counter, false, NULL, NULL, peer);
}

static int melodi_receive_challenge(struct net_device *dev, const void *frame,
                                    size_t length,
                                    const struct melodi_rx_meta *meta)
{
    const u8 *announced;
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_wire_auth response = {};
    struct melodi_wire_auth auth;
    struct melodi_peer *peer;
    u8 ephemeral_private[32];
    u8 ephemeral_public[32];
    u8 shared[32];
    int error;

    error = melodi_wire_decode_auth(frame, length, &auth);
    if (error || auth.common.frame_class != MELODI_WIRE_CHALLENGE)
        return error ? error : -EPROTO;
    error = melodi_identity_verify(&auth.source_node_id, frame,
                                   MELODI_WIRE_AUTH_SIGNED_SIZE,
                                   auth.signature);
    if (error)
        return error;
    curve25519_generate_secret(ephemeral_private);
    if (!curve25519_generate_public(ephemeral_public, ephemeral_private) ||
        !curve25519(shared, ephemeral_private, auth.ephemeral_key)) {
        error = -EKEYREJECTED;
        goto wipe;
    }
    mutex_lock(&melodi->lock);
    error = melodi_auth_validate(melodi, &auth, meta, &peer);
    if (error)
        goto unlock;
    melodi_peer_observe_locked(peer, meta);
    if (!memcmp(auth.reply_to, melodi->last_hello_challenge, 32))
        announced = melodi->last_hello_challenge;
    else if (!memcmp(auth.reply_to, melodi->previous_hello_challenge, 32))
        announced = melodi->previous_hello_challenge;
    else {
        error = -EKEYREJECTED;
        goto unlock;
    }
    melodi_data_peer_reset_locked(melodi, &peer->node_id);
    melodi_session_key(peer->transmit_key, shared, melodi->mesh_domain,
                       &melodi->node_id, &peer->node_id,
                       melodi->local_native_locator, peer->native_locator,
                       melodi->local_collision_round, peer->collision_round,
                       melodi->identity_generation, peer->generation,
                       ephemeral_public, auth.ephemeral_key,
                       announced, auth.challenge, 0);
    melodi_session_key(peer->receive_key, shared, melodi->mesh_domain,
                       &melodi->node_id, &peer->node_id,
                       melodi->local_native_locator, peer->native_locator,
                       melodi->local_collision_round, peer->collision_round,
                       melodi->identity_generation, peer->generation,
                       ephemeral_public, auth.ephemeral_key,
                       announced, auth.challenge, 1);
    melodi_replay_reset(&peer->receive_replay);
    melodi_peer_session_advance(peer);
    peer->session_ready = true;
    response.common.frame_class = MELODI_WIRE_RESPONSE;
    response.common.source_native_locator = melodi->local_native_locator;
    response.common.destination_native_locator = peer->native_locator;
    response.common.identity_generation = melodi->identity_generation;
    response.common.message_id = auth.common.message_id;
    error = melodi_counter_next_locked(melodi, &response.common.counter);
    if (error)
        goto unlock;
    response.source_node_id = melodi->node_id;
    response.destination_node_id = peer->node_id;
    memcpy(response.ephemeral_key, ephemeral_public, 32);
    memcpy(response.challenge, announced, 32);
    memcpy(response.reply_to, auth.challenge, 32);
    memcpy(response.mesh_domain, melodi->mesh_domain, 32);
    response.collision_round = melodi->local_collision_round;
unlock:
    mutex_unlock(&melodi->lock);
    if (!error)
        error = melodi_send_auth(dev, &response);
wipe:
    memzero_explicit(ephemeral_private, sizeof(ephemeral_private));
    memzero_explicit(shared, sizeof(shared));
    return error;
}

static int melodi_receive_response(struct net_device *dev, const void *frame,
                                   size_t length,
                                   const struct melodi_rx_meta *meta)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_wire_auth auth;
    struct melodi_peer *peer;
    u8 shared[32];
    int error;

    error = melodi_wire_decode_auth(frame, length, &auth);
    if (error || auth.common.frame_class != MELODI_WIRE_RESPONSE)
        return error ? error : -EPROTO;
    error = melodi_identity_verify(&auth.source_node_id, frame,
                                   MELODI_WIRE_AUTH_SIGNED_SIZE,
                                   auth.signature);
    if (error)
        return error;
    mutex_lock(&melodi->lock);
    peer = melodi_peer_slot(melodi, &auth.source_node_id);
    if (!peer || !peer->handshake_pending ||
        memcmp(auth.challenge, peer->remote_hello_challenge, 32) ||
        memcmp(auth.reply_to, peer->local_challenge, 32)) {
        error = -EKEYREJECTED;
        goto unlock;
    }
    error = melodi_auth_validate(melodi, &auth, meta, &peer);
    if (error)
        goto unlock;
    melodi_peer_observe_locked(peer, meta);
    if (!curve25519(shared, peer->ephemeral_private, auth.ephemeral_key)) {
        error = -EKEYREJECTED;
        goto unlock;
    }
    melodi_data_peer_reset_locked(melodi, &peer->node_id);
    melodi_session_key(peer->receive_key, shared, melodi->mesh_domain,
                       &peer->node_id, &melodi->node_id,
                       peer->native_locator, melodi->local_native_locator,
                       peer->collision_round, melodi->local_collision_round,
                       peer->generation, melodi->identity_generation,
                       auth.ephemeral_key, peer->ephemeral_public,
                       peer->remote_hello_challenge, peer->local_challenge, 0);
    melodi_session_key(peer->transmit_key, shared, melodi->mesh_domain,
                       &peer->node_id, &melodi->node_id,
                       peer->native_locator, melodi->local_native_locator,
                       peer->collision_round, melodi->local_collision_round,
                       peer->generation, melodi->identity_generation,
                       auth.ephemeral_key, peer->ephemeral_public,
                       peer->remote_hello_challenge, peer->local_challenge, 1);
    melodi_replay_reset(&peer->receive_replay);
    melodi_peer_session_advance(peer);
    peer->session_ready = true;
    peer->handshake_pending = false;
    memzero_explicit(peer->ephemeral_private,
                     sizeof(peer->ephemeral_private));
unlock:
    mutex_unlock(&melodi->lock);
    memzero_explicit(shared, sizeof(shared));
    return error;
}

static int melodi_receive_control(struct net_device *dev, const void *frame,
                                  size_t length,
                                  const struct melodi_rx_meta *meta)
{
    struct melodi_device *melodi = netdev_priv(dev);
    struct melodi_wire_control control;
    struct melodi_peer *peer;
    bool local_changed = false;
    int error;

    error = melodi_wire_decode_control(frame, length, &control);
    if (error)
        return error;
    if (control.opcode != MELODI_CONTROL_PROBE)
        return -EPROTO;
    error = melodi_identity_verify(&control.node_id, frame,
                                   MELODI_WIRE_CONTROL_SIGNED_SIZE,
                                   control.signature);
    if (error)
        return error;
    mutex_lock(&melodi->lock);
    if (memcmp(control.mesh_domain, melodi->mesh_domain, 32))
        error = -EXDEV;
    else
        error = melodi_claim_locked(
            melodi, &control.node_id,
            control.common.source_native_locator,
            meta->source_locator,
            control.collision_round,
            control.common.identity_generation,
            control.common.counter, true, &local_changed, NULL, &peer);
    if (!error) {
        unsigned long expires = jiffies +
            msecs_to_jiffies(MELODI_CONTROL_EXPIRY_SECONDS * 1000U);

        if (!peer->expires || time_before(peer->expires, expires))
            peer->expires = expires;
        melodi_peer_observe_locked(peer, meta);
        melodi_peer_expiry_schedule_locked(melodi);
    }
    mutex_unlock(&melodi->lock);
    if (error)
        return error;
    if (local_changed) {
        melodi_link_ready(dev, false, 0);
        melodi_data_fail_pending(dev, -EADDRINUSE);
        return melodi_transport_configure(dev);
    }
    return netif_running(dev) && netif_carrier_ok(dev) ?
           melodi_discovery_announce(dev) : 0;
}

int melodi_discovery_receive(struct net_device *dev, const void *frame,
                             size_t length,
                             const struct melodi_rx_meta *meta)
{
    struct melodi_wire_common common;
    int error;

    error = melodi_wire_decode_common(frame, length, &common);
    if (error)
        return error;
    if (common.frame_class == MELODI_WIRE_HELLO)
        error = melodi_receive_hello(dev, frame, length, false, meta);
    else if (common.frame_class == MELODI_WIRE_CONFLICT)
        error = melodi_receive_hello(dev, frame, length, true, meta);
    else if (common.frame_class == MELODI_WIRE_CHALLENGE)
        error = melodi_receive_challenge(dev, frame, length, meta);
    else if (common.frame_class == MELODI_WIRE_RESPONSE)
        error = melodi_receive_response(dev, frame, length, meta);
    else if (common.frame_class == MELODI_WIRE_CONTROL)
        error = melodi_receive_control(dev, frame, length, meta);
    else
        return -EPROTO;
    melodi_queue_state_changed(dev);
    melodi_data_state_changed(dev);
    return error;
}
