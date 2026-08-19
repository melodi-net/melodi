/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MELODI_CORE_INTERNAL_H
#define MELODI_CORE_INTERNAL_H

#include <linux/key.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/netdevice.h>
#include <linux/siphash.h>
#include <linux/workqueue.h>
#include <net/net_namespace.h>

#include <melodi/core.h>
#include "airtime.h"
#include "mapping.h"
#include "ordering.h"
#include "reliability.h"
#include "replay.h"

#define MELODI_DEVICE_MAGIC 0x6d656c6fU
#define MELODI_PEER_LIMIT 64
#define MELODI_FRAGMENT_LIMIT 64
#define MELODI_REASSEMBLY_LIMIT 16
#define MELODI_REASSEMBLY_BYTE_LIMIT (MELODI_MESSAGE_MTU * 8)
#define MELODI_REASSEMBLY_TIMEOUT_MS 5000
#define MELODI_POLICY_PEER_LIMIT 64
#define MELODI_POLICY_SERVICE_LIMIT 64
#define MELODI_PENDING_LIMIT 32
#define MELODI_DISCOVERY_TARGET_LIMIT 16
#define MELODI_DISCOVERY_PENDING_LIMIT 32
#define MELODI_DISCOVERY_PER_NODE_LIMIT 4
#define MELODI_DISCOVERY_BYTE_LIMIT (MELODI_MESSAGE_MTU * 8)
#define MELODI_DISCOVERY_TIMEOUT_MS 5000
#define MELODI_PEER_EXPIRY_MAX_SECONDS 300
#define MELODI_ANNOUNCE_JITTER_MS 3000
#define MELODI_ANNOUNCE_RETRY_MS 12000
#define MELODI_ANNOUNCE_SLOTS 4
#define MELODI_CONTROL_EXPIRY_SECONDS 30
#define MELODI_RECEIPT_LIMIT 64
#define MELODI_RECEIPT_TIMEOUT_MS 10000
#define MELODI_ORDER_FLOW_LIMIT 32
#define MELODI_ORDER_BUFFER_LIMIT 64
#define MELODI_ORDER_BYTE_LIMIT (MELODI_MESSAGE_MTU * 8)
#define MELODI_TX_QUEUE_LIMIT 128
#define MELODI_TX_DATA_LIMIT 112
#define MELODI_TX_BYTE_LIMIT (MELODI_MESSAGE_MTU * 64)
#define MELODI_TX_PER_PEER_LIMIT 32
#define MELODI_TX_PER_SERVICE_LIMIT 32
#define MELODI_TX_PER_BINDING_LIMIT 32
#define MELODI_TX_FLOW_LIMIT 64
#define MELODI_TX_HIGH_WATER 96
#define MELODI_TX_LOW_WATER 48
#define MELODI_TX_CONTROL_TTL_MS 5000
#define MELODI_TX_CONTROL_BURST 8
#define MELODI_TX_NAMESPACE_LIMIT 256
#define MELODI_TX_NAMESPACE_BYTE_LIMIT (MELODI_MESSAGE_MTU * 128)
#define MELODI_TX_RESERVATION_LIMIT 128
#define MELODI_LOGICAL_QUEUE_LIMIT 128
#define MELODI_LOGICAL_MAGIC 0x4d454c51U
#define MELODI_LOGICAL_VERSION 1

struct melodi_pending_message {
    struct melodi_reliability_state reliability;
    struct melodi_node_id destination;
    struct sk_buff *fragments[MELODI_FRAGMENT_LIMIT];
    u64 reservation_id;
    u64 cookie;
    u64 expires_ms;
    u64 session_epoch;
    u64 binding_generation;
    u32 source_native_locator;
    u32 destination_native_locator;
    u32 source_link_locator;
    u32 destination_link_locator;
    u32 destination_generation;
    u16 source_service;
    u16 destination_service;
    u32 binding_portid;
    u8 priority;
    bool allocated;
};

struct melodi_discovery_target {
    struct melodi_node_id destination;
    u64 expires_ms;
    bool active;
};

struct melodi_discovery_pending {
    struct melodi_node_id destination;
    u8 *payload;
    u64 cookie;
    u64 expires_ms;
    u64 binding_generation;
    u32 binding_portid;
    u32 flags;
    u32 length;
    u16 source_service;
    u16 destination_service;
    u8 priority;
    bool in_flight;
    bool active;
};

struct melodi_queue_request {
    struct melodi_node_id destination;
    u64 message_id;
    u64 session_epoch;
    u32 ttl_ms;
    u32 binding_portid;
    u32 identity_generation;
    u32 source_locator;
    u64 binding_generation;
    u16 service;
    u16 destination_service;
    u8 priority;
    bool broadcast;
    bool reliable;
    bool control;
};

struct melodi_tx_reservation {
    struct melodi_node_id destination;
    struct net *net;
    u64 id;
    u64 expires_ms;
    u64 binding_generation;
    u64 cookie;
    u64 tag;
    u64 session_epoch;
    u32 locator;
    u32 source_locator;
    u32 binding_portid;
    u32 identity_generation;
    u32 bytes;
    u32 logical_length;
    u16 count;
    u16 service;
    u16 destination_service;
    u8 priority;
    u8 peer_index;
    u8 flow_index;
    bool pending_reserved;
    bool broadcast;
    bool reliable;
    bool claimed;
    bool sealed;
    bool active;
};

struct melodi_logical_header {
    struct melodi_node_id destination;
    u64 reservation_id;
    u64 cookie;
    u64 binding_generation;
    u32 magic;
    u32 flags;
    u32 ttl_ms;
    u32 binding_portid;
    u32 payload_length;
    u16 source_service;
    u16 destination_service;
    u16 header_length;
    u8 priority;
    u8 version;
};

struct melodi_tx_queue_entry {
    struct melodi_node_id destination;
    struct sk_buff *frame;
    struct net *net;
    struct melodi_tx_meta metadata;
    u64 sequence;
    u64 group_id;
    u64 message_id;
    u64 session_epoch;
    u64 expires_ms;
    u64 defer_until_ms;
    u64 binding_generation;
    u32 binding_portid;
    u32 identity_generation;
    u32 length;
    u16 service;
    u16 destination_service;
    u8 priority;
    u8 peer_index;
    u8 flow_index;
    bool control;
    bool broadcast;
    bool reliable;
    bool cancelled;
    bool terminal_notified;
    bool in_flight;
    bool active;
};

struct melodi_tx_peer_turn {
    u64 turn;
    u32 locator;
    bool active;
};

struct melodi_tx_flow_turn {
    u64 turn;
    u64 binding_generation;
    u32 locator;
    u32 binding_portid;
    u16 service;
    u8 peer_index;
    bool active;
};

struct melodi_receipt {
    struct melodi_node_id source;
    u64 message_id;
    u64 bitmap;
    u64 session_epoch;
    unsigned long expires;
    u32 generation;
    u16 fragment_count;
    u8 status;
    bool active;
};

struct melodi_order_tx_flow {
    struct melodi_node_id destination;
    u64 session_epoch;
    u32 generation;
    u32 next_marker;
    u16 source_service;
    u16 destination_service;
    bool active;
};

struct melodi_order_rx_flow {
    struct melodi_order_state state;
    struct melodi_node_id source;
    u64 session_epoch;
    u32 generation;
    u16 source_service;
    u16 destination_service;
    bool active;
};

struct melodi_order_message {
    struct melodi_node_id source;
    struct melodi_rx_meta metadata;
    u8 *payload;
    size_t length;
    u32 marker;
    u16 source_service;
    u16 destination_service;
    u8 flow_index;
    bool active;
};

struct melodi_policy_peer {
    struct melodi_node_id node_id;
    enum melodi_peer_state state;
    bool active;
};

struct melodi_policy_service {
    u16 service;
    u8 action;
    bool active;
};

struct melodi_fragment {
    u8 *data;
    u16 length;
};

struct melodi_reassembly {
    struct melodi_node_id source;
    struct melodi_rx_meta metadata;
    u64 message_id;
    u64 session_epoch;
    unsigned long expires;
    u64 received;
    u32 generation;
    u32 logical_length;
    u32 received_length;
    u32 ordering_marker;
    u16 source_service;
    u16 destination_service;
    u16 fragment_count;
    u16 flags;
    u8 delivery_mode;
    u8 priority;
    bool active;
    struct melodi_fragment fragments[MELODI_FRAGMENT_LIMIT];
};

struct melodi_peer {
    struct melodi_node_id node_id;
    u32 native_locator;
    u32 link_locator;
    u32 collision_round;
    u32 generation;
    u64 control_counter;
    unsigned long expires;
    u32 capabilities;
    u64 last_seen_ns;
    s16 rssi;
    s16 snr;
    u8 hops;
    struct melodi_replay_window receive_replay;
    u64 session_epoch;
    u8 transmit_key[32];
    u8 receive_key[32];
    u8 ephemeral_private[32];
    u8 ephemeral_public[32];
    u8 remote_hello_challenge[32];
    u8 local_challenge[32];
    bool authenticated;
    bool conflicted;
    bool handshake_pending;
    bool session_ready;
};

struct melodi_transport {
    const struct melodi_link_ops *ops;
    struct module *owner;
    struct device *parent;
    size_t private_size;
    refcount_t references;
    struct completion released;
    u8 private_data[];
};

struct melodi_device {
    u32 magic;
    struct net_device *netdev;
    struct mutex lock;
    siphash_key_t logical_key;
    struct melodi_transport *transport;
    struct melodi_node_id node_id;
    struct key *identity_key;
    bool identity_ready;
    bool transport_ready;
    bool persistent;
    enum melodi_link_state link_state;
    enum melodi_link_failure link_failure;
    int link_error;
    char radio_serial[MELODI_RADIO_SERIAL_MAX + 1];
    u8 mesh_domain[MELODI_MESH_DOMAIN_SIZE];
    u32 local_native_locator;
    u32 local_link_locator;
    u32 local_collision_round;
    u32 identity_generation;
    u64 transmit_counter;
    u8 last_hello_challenge[32];
    u8 previous_hello_challenge[32];
    struct melodi_peer peers[MELODI_PEER_LIMIT];
    struct delayed_work peer_expiry_work;
    struct delayed_work announce_work;
    u32 reassembly_bytes;
    bool conflict_pending;
    struct melodi_reassembly reassemblies[MELODI_REASSEMBLY_LIMIT];
    struct delayed_work reassembly_work;
    struct melodi_receipt receipts[MELODI_RECEIPT_LIMIT];
    struct melodi_order_tx_flow order_tx[MELODI_ORDER_FLOW_LIMIT];
    struct melodi_order_rx_flow order_rx[MELODI_ORDER_FLOW_LIMIT];
    struct melodi_order_message order_messages[MELODI_ORDER_BUFFER_LIMIT];
    u32 order_bytes;
    struct melodi_pending_message pending[MELODI_PENDING_LIMIT];
    struct delayed_work reliability_work;
    struct melodi_discovery_target
        discovery_targets[MELODI_DISCOVERY_TARGET_LIMIT];
    struct melodi_discovery_pending
        discovery_pending[MELODI_DISCOVERY_PENDING_LIMIT];
    struct delayed_work discovery_work;
    u32 discovery_bytes;
    u16 discovery_count;
    struct melodi_tx_queue_entry tx_queue[MELODI_TX_QUEUE_LIMIT];
    struct melodi_tx_reservation
        tx_reservations[MELODI_TX_RESERVATION_LIMIT];
    struct melodi_tx_peer_turn tx_peers[MELODI_TX_FLOW_LIMIT];
    struct melodi_tx_flow_turn tx_flows[MELODI_TX_FLOW_LIMIT];
    struct delayed_work tx_queue_work;
    struct delayed_work tx_reservation_work;
    struct sk_buff_head logical_tx_queue;
    struct work_struct logical_tx_work;
    struct melodi_airtime_window tx_airtime;
    struct melodi_airtime_window tx_broadcast_airtime;
    struct melodi_airtime_window tx_airtime_after;
    struct melodi_airtime_window tx_broadcast_after;
    u64 tx_guard_until_ms;
    u64 tx_queue_sequence;
    u64 tx_group_sequence;
    u64 tx_reservation_sequence;
    u64 tx_scheduler_turn;
    u64 tx_airtime_budget_us;
    u64 tx_broadcast_budget_us;
    u32 tx_queue_bytes;
    u32 tx_reserved_bytes;
    u16 tx_queue_count;
    u16 tx_reserved_count;
    u16 tx_pending_reserved;
    u8 tx_priority_slot;
    u8 tx_control_burst;
    bool tx_queue_stopping;
    bool logical_tx_stopping;
    atomic64_t auth_failures;
    atomic64_t replay_drops;
    atomic64_t broadcast_tx;
    atomic64_t broadcast_rx;
    atomic64_t duty_defers;
    atomic64_t queue_expired;
    atomic64_t app_delivery_drops;
    atomic64_t monitor_drops;
    enum melodi_policy_mode policy_mode;
    bool broadcast_allowed;
    struct melodi_policy_peer policy_peers[MELODI_POLICY_PEER_LIMIT];
    struct melodi_policy_service
        policy_services[MELODI_POLICY_SERVICE_LIMIT];
};

struct melodi_stats_snapshot {
    u64 values[MELODI_STAT_A_MAX + 1];
};

struct melodi_binding {
    struct list_head node;
    struct net *net;
    struct net_device *dev;
    u64 generation;
    u32 portid;
    u16 service;
    bool module_held;
};

extern struct genl_family melodi_genl_family;

struct net_device *melodi_device_get(struct net *net, int ifindex);
bool melodi_device_is(const struct net_device *dev);
bool melodi_node_id_valid(const struct melodi_node_id *node_id);
bool melodi_device_identity(struct net_device *dev,
                            struct melodi_node_id *node_id,
                            u32 *generation);
int melodi_device_set_identity(struct net_device *dev,
                               const struct melodi_node_id *node_id,
                               struct key *identity_key, u32 generation,
                               const struct melodi_node_id *previous_node_id);
int melodi_core_send(struct net_device *dev, struct sk_buff *skb,
                     const struct melodi_tx_meta *meta);
int melodi_core_send_batch(struct net_device *dev, struct sk_buff **frames,
                           u16 count, const struct melodi_tx_meta *meta,
                           const struct melodi_queue_request *request);
int melodi_core_send_batch_reserved(
    struct net_device *dev, struct sk_buff **frames, u16 count,
    const struct melodi_tx_meta *meta,
    const struct melodi_queue_request *request, u64 reservation_id);
int melodi_core_xmit(struct net_device *dev, struct sk_buff *skb,
                     const struct melodi_tx_meta *meta);
int melodi_core_airtime(struct net_device *dev, const struct sk_buff *skb,
                        const struct melodi_tx_meta *meta,
                        struct melodi_airtime_charge *charge);
int melodi_core_link_info(struct net_device *dev,
                          struct melodi_link_info *info);
void melodi_queue_init(struct melodi_device *melodi);
void melodi_queue_start(struct net_device *dev);
void melodi_queue_pause(struct net_device *dev);
void melodi_queue_stop(struct net_device *dev);
void melodi_queue_fail(struct net_device *dev, int error);
void melodi_queue_state_changed(struct net_device *dev);
int melodi_queue_reserve(struct net_device *dev, struct net *net, u32 locator,
                         const struct melodi_queue_request *request,
                         u16 count, u32 bytes, u32 logical_length, u64 cookie,
                         bool reliable, u16 active_pending, u64 *reservation);
void melodi_queue_reservation_cancel(struct net_device *dev, u64 reservation,
                                     int error, bool notify);
int melodi_queue_reservation_pending(struct net_device *dev,
                                     u64 reservation);
int melodi_queue_reservation_seal(struct net_device *dev, u64 reservation,
                                  const void *data, size_t length);
int melodi_queue_reservation_claim(struct net_device *dev, u64 reservation,
                                   const void *data, size_t length);
int melodi_queue_reservation_locator(struct net_device *dev, u64 reservation,
                                     u32 *locator);
void melodi_queue_stats(struct net_device *dev, u64 *frames, u64 *bytes,
                        u64 *airtime_us, u64 *broadcast_airtime_us);
bool melodi_queue_message_queued(struct net_device *dev,
                                 const struct melodi_node_id *destination,
                                 u64 message_id, u32 binding_portid,
                                 u64 binding_generation, u16 service);
int melodi_counter_next_locked(struct melodi_device *melodi, u64 *counter);
u32 melodi_core_frame_mtu(struct net_device *dev);
u32 melodi_core_frame_pace_ms(struct net_device *dev);
bool melodi_core_link_busy(struct net_device *dev);
int melodi_identity_key_matches(struct key *key,
                                const struct melodi_node_id *node_id);
int melodi_identity_sign(struct net_device *dev, const void *message,
                         size_t length, u8 signature[64]);
int melodi_identity_verify(const struct melodi_node_id *node_id,
                           const void *message, size_t length,
                           const u8 signature[64]);
int melodi_netlink_register(void);
void melodi_netlink_unregister(void);
void melodi_netlink_interface_removed(struct net_device *dev);
void melodi_namespace_reset(struct net_device *dev);
void melodi_netlink_delivery_error(struct net_device *dev,
                                   u32 binding_portid,
                                   u64 binding_generation,
                                   u16 source_service, u64 cookie, int error);
void melodi_netlink_link_error(struct net_device *dev, int error);
int melodi_netlink_receive(struct net_device *dev,
                           const struct melodi_node_id *source,
                           u16 source_service, u16 destination_service,
                           const void *payload, size_t length,
                           const struct melodi_rx_meta *meta);
void melodi_netlink_monitor_frame(struct net_device *dev, u8 direction,
                                  const void *frame, size_t length,
                                  const struct melodi_rx_meta *meta);
void melodi_stats_read(struct net_device *dev,
                       struct melodi_stats_snapshot *snapshot);
int melodi_discovery_announce(struct net_device *dev);
void melodi_discovery_announce_soon(struct net_device *dev);
int melodi_discovery_probe(struct net_device *dev);
int melodi_discovery_receive(struct net_device *dev, const void *frame,
                             size_t length,
                             const struct melodi_rx_meta *meta);
void melodi_peer_observe_locked(struct melodi_peer *peer,
                                const struct melodi_rx_meta *meta);
void melodi_peer_session_reset_locked(struct melodi_device *melodi,
                                      struct melodi_peer *peer);
void melodi_discovery_init(struct melodi_device *melodi);
void melodi_discovery_stop(struct melodi_device *melodi);
void melodi_discovery_reset_locked(struct melodi_device *melodi);
int melodi_data_send(struct net_device *dev,
                     const struct melodi_node_id *destination,
                     u16 source_service, u16 destination_service,
                     const void *payload, size_t length, u32 flags,
                     u64 cookie, u32 ttl_ms, u32 binding_portid,
                     u64 binding_generation, u8 priority);
int melodi_data_admit(struct net_device *dev,
                      const struct melodi_node_id *destination,
                      u16 source_service, u16 destination_service,
                      size_t length, u32 flags, u64 cookie, u32 ttl_ms,
                      u32 binding_portid, u64 binding_generation, u8 priority,
                      u64 *reservation);
int melodi_data_send_reserved(struct net_device *dev,
                              const struct melodi_node_id *destination,
                              u16 source_service, u16 destination_service,
                              const void *payload, size_t length, u32 flags,
                              u64 cookie, u32 ttl_ms, u32 binding_portid,
                              u64 binding_generation, u8 priority,
                              u64 reservation);
int melodi_data_receive(struct net_device *dev, const void *frame,
                        size_t length, const struct melodi_rx_meta *meta);
int melodi_data_receive_ack(struct net_device *dev, const void *frame,
                            size_t length,
                            const struct melodi_rx_meta *meta);
void melodi_data_reset_locked(struct melodi_device *melodi);
void melodi_data_reassembly_reset_locked(struct melodi_device *melodi);
void melodi_data_order_reset_locked(struct melodi_device *melodi);
void melodi_data_peer_reset_locked(struct melodi_device *melodi,
                                   const struct melodi_node_id *node_id);
void melodi_data_fail_pending(struct net_device *dev, int error);
void melodi_data_state_changed(struct net_device *dev);
bool melodi_data_cancel_pending_locked(
    struct melodi_device *melodi,
    const struct melodi_node_id *destination, u64 message_id,
    u64 reservation_id);
int melodi_data_queue_valid_locked(
    struct melodi_device *melodi,
    const struct melodi_node_id *destination, u16 destination_service,
    bool broadcast, const struct melodi_tx_meta *metadata,
    u32 identity_generation, u64 session_epoch);
void melodi_data_init(struct melodi_device *melodi);
void melodi_data_stop(struct melodi_device *melodi);
int melodi_policy_check_locked(struct melodi_device *melodi,
                               const struct melodi_node_id *node_id);
int melodi_policy_check_service_locked(struct melodi_device *melodi,
                                       u16 service, bool broadcast);
int melodi_policy_check_message_locked(
    struct melodi_device *melodi,
    const struct melodi_node_id *destination, u16 destination_service,
    bool broadcast);
enum melodi_peer_state
melodi_policy_peer_state_locked(struct melodi_device *melodi,
                                const struct melodi_peer *peer);
enum melodi_peer_policy
melodi_policy_peer_policy_locked(struct melodi_device *melodi,
                                 const struct melodi_peer *peer);
int melodi_policy_set_peer(struct net_device *dev,
                           const struct melodi_node_id *node_id,
                           enum melodi_peer_state state);
int melodi_policy_clear_peer(struct net_device *dev,
                             const struct melodi_node_id *node_id);
int melodi_policy_set_service(struct net_device *dev, u16 service,
                              enum melodi_policy_action action);
int melodi_policy_set_broadcast(struct net_device *dev, bool allowed);
int melodi_policy_set_mode(struct net_device *dev,
                           enum melodi_policy_mode mode);
int melodi_policy_reset(struct net_device *dev);
int melodi_policy_reverify_peer(struct net_device *dev,
                                const struct melodi_node_id *node_id);

#endif
