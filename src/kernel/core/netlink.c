/* SPDX-License-Identifier: GPL-2.0-only */
#include "internal.h"

#include <linux/capability.h>
#include <linux/bitmap.h>
#include <linux/key.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <keys/user-type.h>
#include <net/genetlink.h>
#include <net/net_namespace.h>

static LIST_HEAD(melodi_bindings);
static LIST_HEAD(melodi_monitors);
static DEFINE_MUTEX(melodi_bindings_lock);
static atomic64_t melodi_binding_generation = ATOMIC64_INIT(0);

struct melodi_monitor {
    struct list_head node;
    struct net *net;
    struct net_device *dev;
    u32 portid;
    bool module_held;
};

static void melodi_binding_free(struct melodi_binding *binding)
{
    bool module_held = binding->module_held;

    dev_put(binding->dev);
    put_net(binding->net);
    kfree(binding);
    if (module_held)
        module_put(THIS_MODULE);
}

static void melodi_monitor_free(struct melodi_monitor *monitor)
{
    bool module_held = monitor->module_held;

    dev_put(monitor->dev);
    put_net(monitor->net);
    kfree(monitor);
    if (module_held)
        module_put(THIS_MODULE);
}

static void melodi_binding_error(struct melodi_binding *binding, int code,
                                 bool has_cookie, u64 cookie)
{
    struct nlattr *nested;
    struct sk_buff *message;
    void *header;

    message = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!message)
        return;
    header = genlmsg_put(message, 0, 0, &melodi_genl_family, 0,
                         MELODI_CMD_ERROR);
    if (!header)
        goto free;
    if (nla_put_u32(message, MELODI_A_IFINDEX,
                    binding->dev->ifindex) ||
        nla_put_u16(message, MELODI_A_LOCAL_SERVICE, binding->service) ||
        (has_cookie && nla_put(message, MELODI_A_COOKIE,
                               sizeof(cookie), &cookie)))
        goto free;
    nested = nla_nest_start(message, MELODI_A_ERROR);
    if (!nested)
        goto free;
    if (nla_put_s32(message, MELODI_ERROR_A_CODE, code))
        goto free;
    nla_nest_end(message, nested);
    genlmsg_end(message, header);
    genlmsg_unicast(binding->net, message, binding->portid);
    return;
free:
    nlmsg_free(message);
}

static const struct nla_policy melodi_policy[MELODI_A_MAX + 1] = {
    [MELODI_A_IFINDEX] = { .type = NLA_U32 },
    [MELODI_A_LOCAL_SERVICE] = { .type = NLA_U16 },
    [MELODI_A_DEST_NODE] = NLA_POLICY_EXACT_LEN(MELODI_NODE_ID_SIZE),
    [MELODI_A_DEST_SERVICE] = { .type = NLA_U16 },
    [MELODI_A_SOURCE_NODE] = NLA_POLICY_EXACT_LEN(MELODI_NODE_ID_SIZE),
    [MELODI_A_SOURCE_SERVICE] = { .type = NLA_U16 },
    [MELODI_A_PAYLOAD] = NLA_POLICY_RANGE(NLA_BINARY, 0, MELODI_MESSAGE_MTU),
    [MELODI_A_FLAGS] = { .type = NLA_U32 },
    [MELODI_A_COOKIE] = { .type = NLA_U64 },
    [MELODI_A_TTL_MS] = { .type = NLA_U32 },
    [MELODI_A_PRIORITY] = NLA_POLICY_MAX(NLA_U8, MELODI_PRIORITY_MAX),
    [MELODI_A_RX_META] = { .type = NLA_NESTED },
    [MELODI_A_ERROR] = { .type = NLA_NESTED },
    [MELODI_A_NODE_ID] = NLA_POLICY_EXACT_LEN(MELODI_NODE_ID_SIZE),
    [MELODI_A_KEY_SERIAL] = { .type = NLA_U32 },
    [MELODI_A_LINK_STATE] = NLA_POLICY_MAX(NLA_U8, MELODI_LINK_FAILED),
    [MELODI_A_PEER_NATIVE_LOCATOR] = { .type = NLA_U32 },
    [MELODI_A_COLLISION_ROUND] = { .type = NLA_U32 },
    [MELODI_A_PEER_STATE] = NLA_POLICY_MAX(NLA_U8,
                                            MELODI_PEER_CHALLENGED),
    [MELODI_A_GENERATION] = { .type = NLA_U32 },
    [MELODI_A_POLICY_MODE] = NLA_POLICY_MAX(NLA_U8,
                                             MELODI_POLICY_REQUIRE_TRUST),
    [MELODI_A_LINK_FAILURE] = NLA_POLICY_MAX(NLA_U16,
                                             MELODI_LINK_FAILURE_MAX),
    [MELODI_A_LINK_ERROR] = { .type = NLA_S32 },
    [MELODI_A_RADIO_SERIAL] = {
        .type = NLA_NUL_STRING,
        .len = MELODI_RADIO_SERIAL_MAX,
    },
    [MELODI_A_STATS] = { .type = NLA_NESTED },
    [MELODI_A_MONITOR_DIRECTION] =
        NLA_POLICY_MAX(NLA_U8, MELODI_MONITOR_TX),
    [MELODI_A_FRAME] = { .type = NLA_BINARY, .len = MELODI_FRAME_MTU_MAX },
    [MELODI_A_BUS_INFO] = {
        .type = NLA_NUL_STRING,
        .len = MELODI_BUS_INFO_MAX,
    },
    [MELODI_A_PREVIOUS_NODE_ID] =
        NLA_POLICY_EXACT_LEN(MELODI_NODE_ID_SIZE),
    [MELODI_A_POLICY_SERVICE] = { .type = NLA_U16 },
    [MELODI_A_POLICY_ACTION] =
        NLA_POLICY_RANGE(NLA_U8, MELODI_POLICY_SERVICE_ALLOW,
                         MELODI_POLICY_SERVICE_CLEAR),
    [MELODI_A_POLICY_BROADCAST] = NLA_POLICY_MAX(NLA_U8, 1),
    [MELODI_A_PEER_EXPIRY_MS] = { .type = NLA_U32 },
    [MELODI_A_PEER_CAPABILITIES] = { .type = NLA_U32 },
    [MELODI_A_PEER_RSSI] = { .type = NLA_S16 },
    [MELODI_A_PEER_SNR] = { .type = NLA_S16 },
    [MELODI_A_PEER_HOPS] = { .type = NLA_U8 },
    [MELODI_A_PEER_LAST_SEEN_NS] = { .type = NLA_U64 },
    [MELODI_A_PEER_POLICY] =
        NLA_POLICY_MAX(NLA_U8, MELODI_PEER_POLICY_BLOCKED),
    [MELODI_A_POLICY_RESET] = NLA_POLICY_RANGE(NLA_U8, 1, 1),
    [MELODI_A_FRAME_PACE_US] = { .type = NLA_U32 },
};

static u64 melodi_allowed_attributes(u8 command)
{
    switch (command) {
    case MELODI_CMD_BIND:
        return BIT_ULL(MELODI_A_IFINDEX) |
               BIT_ULL(MELODI_A_LOCAL_SERVICE);
    case MELODI_CMD_UNBIND:
    case MELODI_CMD_GET_BINDING:
        return 0;
    case MELODI_CMD_SEND:
        return BIT_ULL(MELODI_A_DEST_NODE) |
               BIT_ULL(MELODI_A_DEST_SERVICE) |
               BIT_ULL(MELODI_A_PAYLOAD) |
               BIT_ULL(MELODI_A_FLAGS) |
               BIT_ULL(MELODI_A_COOKIE) |
               BIT_ULL(MELODI_A_TTL_MS) |
               BIT_ULL(MELODI_A_PRIORITY);
    case MELODI_CMD_LINK_GET:
    case MELODI_CMD_IDENTITY_GET_PUBLIC:
        return BIT_ULL(MELODI_A_IFINDEX);
    case MELODI_CMD_LINK_SET:
        return BIT_ULL(MELODI_A_IFINDEX) |
               BIT_ULL(MELODI_A_RADIO_SERIAL);
    case MELODI_CMD_IDENTITY_LOAD:
        return BIT_ULL(MELODI_A_IFINDEX) |
               BIT_ULL(MELODI_A_NODE_ID) |
               BIT_ULL(MELODI_A_KEY_SERIAL) |
               BIT_ULL(MELODI_A_GENERATION) |
               BIT_ULL(MELODI_A_PREVIOUS_NODE_ID);
    case MELODI_CMD_PEER_DUMP:
        return BIT_ULL(MELODI_A_IFINDEX);
    case MELODI_CMD_PEER_TRUST:
    case MELODI_CMD_PEER_BLOCK:
    case MELODI_CMD_PEER_CLEAR:
    case MELODI_CMD_PEER_REVERIFY:
        return BIT_ULL(MELODI_A_IFINDEX) |
               BIT_ULL(MELODI_A_NODE_ID);
    case MELODI_CMD_POLICY_GET:
        return BIT_ULL(MELODI_A_IFINDEX);
    case MELODI_CMD_POLICY_SET:
        return BIT_ULL(MELODI_A_IFINDEX) |
               BIT_ULL(MELODI_A_POLICY_MODE) |
               BIT_ULL(MELODI_A_POLICY_SERVICE) |
               BIT_ULL(MELODI_A_POLICY_ACTION) |
               BIT_ULL(MELODI_A_POLICY_BROADCAST) |
               BIT_ULL(MELODI_A_POLICY_RESET);
    case MELODI_CMD_DISCOVER:
    case MELODI_CMD_STATS_GET:
    case MELODI_CMD_MONITOR_BIND:
        return BIT_ULL(MELODI_A_IFINDEX);
    default:
        return 0;
    }
}

static int melodi_pre_doit(const struct genl_split_ops *ops,
                           struct sk_buff *skb, struct genl_info *info)
{
    DECLARE_BITMAP(seen, MELODI_A_MAX + 1);
    const struct nlattr *attribute;
    const u8 *padding;
    u64 allowed;
    int remaining;
    int pad_length;
    int type;

    (void)ops;
    (void)skb;
    if (info->genlhdr->version != MELODI_GENL_VERSION ||
        info->genlhdr->reserved != 0)
        return -EPROTO;
    bitmap_zero(seen, MELODI_A_MAX + 1);
    allowed = melodi_allowed_attributes(info->genlhdr->cmd);
    nla_for_each_attr(attribute, genlmsg_data(info->genlhdr),
                      genlmsg_len(info->genlhdr), remaining) {
        type = nla_type(attribute);
        if (type == MELODI_A_UNSPEC || type > MELODI_A_MAX ||
            !(allowed & BIT_ULL(type)) || test_and_set_bit(type, seen))
            return -EINVAL;
        if (attribute->nla_type & (NLA_F_NESTED | NLA_F_NET_BYTEORDER))
            return -EINVAL;
        padding = (const u8 *)attribute + attribute->nla_len;
        pad_length = NLA_ALIGN(attribute->nla_len) - attribute->nla_len;
        while (pad_length-- > 0)
            if (*padding++ != 0)
                return -EPROTO;
    }
    return remaining == 0 ? 0 : -EPROTO;
}

static struct melodi_binding *melodi_binding_by_socket(struct net *net,
                                                       u32 portid)
{
    struct melodi_binding *binding;

    list_for_each_entry(binding, &melodi_bindings, node)
        if (binding->net == net && binding->portid == portid)
            return binding;
    return NULL;
}

static bool melodi_service_bound(struct net_device *dev, u16 service)
{
    struct melodi_binding *binding;

    list_for_each_entry(binding, &melodi_bindings, node)
        if (binding->dev == dev && binding->service == service)
            return true;
    return false;
}

static struct melodi_binding *melodi_binding_by_service(struct net_device *dev,
                                                        u16 service)
{
    struct melodi_binding *binding;

    list_for_each_entry(binding, &melodi_bindings, node)
        if (binding->dev == dev && binding->service == service)
            return binding;
    return NULL;
}

static struct melodi_binding *melodi_binding_by_token(
    struct net_device *dev, u32 portid, u64 generation, u16 service)
{
    struct melodi_binding *binding;

    list_for_each_entry(binding, &melodi_bindings, node)
        if (binding->dev == dev && binding->portid == portid &&
            binding->generation == generation &&
            binding->service == service)
            return binding;
    return NULL;
}

static int melodi_bind(struct sk_buff *skb, struct genl_info *info)
{
    struct melodi_binding *binding;
    struct melodi_device *melodi;
    struct net_device *dev;
    struct net *net = genl_info_net(info);
    int ifindex;
    u16 service;
    int error = 0;

    if (!info->attrs[MELODI_A_IFINDEX] ||
        !info->attrs[MELODI_A_LOCAL_SERVICE])
        return -EINVAL;
    ifindex = nla_get_u32(info->attrs[MELODI_A_IFINDEX]);
    service = nla_get_u16(info->attrs[MELODI_A_LOCAL_SERVICE]);
    if (service == MELODI_SERVICE_CONTROL || service == MELODI_SERVICE_ECHO)
        return -EACCES;
    dev = melodi_device_get(net, ifindex);
    if (!dev)
        return -ENODEV;
    if (!melodi_device_identity(dev, NULL, NULL)) {
        dev_put(dev);
        return -ENOKEY;
    }
    melodi = netdev_priv(dev);
    mutex_lock(&melodi->lock);
    error = melodi_policy_check_service_locked(melodi, service, false);
    mutex_unlock(&melodi->lock);
    if (error) {
        dev_put(dev);
        return error;
    }
    binding = kzalloc(sizeof(*binding), GFP_KERNEL);
    if (!binding) {
        dev_put(dev);
        return -ENOMEM;
    }
    binding->net = get_net(net);
    binding->dev = dev;
    binding->portid = info->snd_portid;
    binding->service = service;
    do {
        binding->generation = atomic64_inc_return(
            &melodi_binding_generation);
    } while (!binding->generation);
    mutex_lock(&melodi_bindings_lock);
    if (melodi_binding_by_socket(net, info->snd_portid))
        error = -EALREADY;
    else if (melodi_service_bound(dev, service))
        error = -EADDRINUSE;
    else {
        __module_get(THIS_MODULE);
        binding->module_held = true;
        list_add_tail(&binding->node, &melodi_bindings);
    }
    mutex_unlock(&melodi_bindings_lock);
    if (error)
        melodi_binding_free(binding);
    return error;
}

static int melodi_unbind(struct sk_buff *skb, struct genl_info *info)
{
    struct melodi_binding *binding;
    struct net *net = genl_info_net(info);

    mutex_lock(&melodi_bindings_lock);
    binding = melodi_binding_by_socket(net, info->snd_portid);
    if (binding)
        list_del(&binding->node);
    mutex_unlock(&melodi_bindings_lock);
    if (!binding)
        return -ENOENT;
    melodi_binding_free(binding);
    return 0;
}

static int melodi_get_binding(struct sk_buff *skb, struct genl_info *info)
{
    struct melodi_binding *binding;
    struct sk_buff *reply;
    void *header;
    int error;

    reply = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!reply)
        return -ENOMEM;
    header = genlmsg_put_reply(reply, info, &melodi_genl_family, 0,
                               MELODI_CMD_GET_BINDING);
    if (!header) {
        nlmsg_free(reply);
        return -EMSGSIZE;
    }
    mutex_lock(&melodi_bindings_lock);
    binding = melodi_binding_by_socket(genl_info_net(info), info->snd_portid);
    if (!binding) {
        mutex_unlock(&melodi_bindings_lock);
        nlmsg_free(reply);
        return -ENOENT;
    }
    error = nla_put_u32(reply, MELODI_A_IFINDEX,
                        binding->dev->ifindex);
    if (!error)
        error = nla_put_u16(reply, MELODI_A_LOCAL_SERVICE, binding->service);
    mutex_unlock(&melodi_bindings_lock);
    if (error) {
        nlmsg_free(reply);
        return error;
    }
    genlmsg_end(reply, header);
    return genlmsg_reply(reply, info);
}

static int melodi_send(struct sk_buff *skb, struct genl_info *info)
{
    struct melodi_logical_header logical;
    struct melodi_node_id destination;
    struct melodi_binding *binding;
    struct sk_buff *message;
    struct net_device *dev;
    struct net *net = genl_info_net(info);
    const void *payload;
    size_t length;
    u64 cookie = 0;
    u64 binding_generation;
    u64 reservation;
    u32 flags = 0;
    u32 ttl_ms = MELODI_TTL_DEFAULT_MS;
    u16 source_service;
    u16 destination_service;
    u8 priority = 0;
    bool broadcast;
    int error;

    memset(&logical, 0, sizeof(logical));
    logical.magic = MELODI_LOGICAL_MAGIC;
    logical.header_length = sizeof(logical);
    logical.version = MELODI_LOGICAL_VERSION;
    if (!info->attrs[MELODI_A_DEST_SERVICE] ||
        !info->attrs[MELODI_A_PAYLOAD])
        return -EINVAL;
    if (info->attrs[MELODI_A_FLAGS])
        flags = nla_get_u32(info->attrs[MELODI_A_FLAGS]);
    if (flags & ~MELODI_F_ALL)
        return -EINVAL;
    broadcast = flags & MELODI_F_BROADCAST;
    if (broadcast == !!info->attrs[MELODI_A_DEST_NODE])
        return -EINVAL;
    if (broadcast && !netlink_capable(skb, CAP_NET_RAW))
        return -EPERM;
    if (!broadcast)
        memcpy(&destination, nla_data(info->attrs[MELODI_A_DEST_NODE]),
               sizeof(destination));
    destination_service = nla_get_u16(info->attrs[MELODI_A_DEST_SERVICE]);
    payload = nla_data(info->attrs[MELODI_A_PAYLOAD]);
    length = nla_len(info->attrs[MELODI_A_PAYLOAD]);
    if (broadcast &&
        (flags & (MELODI_F_RELIABLE | MELODI_F_ORDERED)))
        return -EOPNOTSUPP;
    if (broadcast && length > MELODI_BROADCAST_MTU)
        return -EMSGSIZE;
    if (info->attrs[MELODI_A_COOKIE])
        cookie = nla_get_u64(info->attrs[MELODI_A_COOKIE]);
    if (info->attrs[MELODI_A_PRIORITY])
        priority = nla_get_u8(info->attrs[MELODI_A_PRIORITY]);
    if (info->attrs[MELODI_A_TTL_MS]) {
        ttl_ms = nla_get_u32(info->attrs[MELODI_A_TTL_MS]);
        if (!ttl_ms || ttl_ms > MELODI_TTL_DEFAULT_MS)
            return -EINVAL;
    }
    mutex_lock(&melodi_bindings_lock);
    binding = melodi_binding_by_socket(net, info->snd_portid);
    if (!binding) {
        mutex_unlock(&melodi_bindings_lock);
        return -ENOTCONN;
    }
    if (binding->net != net || dev_net(binding->dev) != net) {
        mutex_unlock(&melodi_bindings_lock);
        return -ENODEV;
    }
    source_service = binding->service;
    binding_generation = binding->generation;
    dev = binding->dev;
    dev_hold(dev);
    mutex_unlock(&melodi_bindings_lock);
    error = melodi_data_admit(
        dev, broadcast ? NULL : &destination, source_service,
        destination_service, length, flags, cookie, ttl_ms,
        info->snd_portid, binding_generation, priority, &reservation);
    if (error)
        goto put_dev;
    message = alloc_skb(sizeof(logical) + length, GFP_KERNEL);
    if (!message) {
        error = -ENOMEM;
        goto cancel;
    }
    if (!broadcast)
        logical.destination = destination;
    logical.reservation_id = reservation;
    logical.cookie = cookie;
    logical.binding_generation = binding_generation;
    logical.flags = flags;
    logical.ttl_ms = ttl_ms;
    logical.binding_portid = info->snd_portid;
    logical.payload_length = length;
    logical.source_service = source_service;
    logical.destination_service = destination_service;
    logical.priority = priority;
    skb_put_data(message, &logical, sizeof(logical));
    if (length)
        skb_put_data(message, payload, length);
    message->dev = dev;
    message->protocol = 0;
    message->priority = priority;
    skb_set_queue_mapping(message, priority);
    error = melodi_queue_reservation_seal(
        dev, reservation, message->data, message->len);
    if (error) {
        kfree_skb(message);
        goto cancel;
    }
    error = dev_queue_xmit(message);
    if (net_xmit_eval(error)) {
        error = error < 0 ? error : net_xmit_errno(error);
        goto cancel;
    }
    error = 0;
    goto put_dev;
cancel:
    melodi_queue_reservation_cancel(dev, reservation, error, false);
put_dev:
    dev_put(dev);
    return error;
}

static int melodi_identity_load(struct sk_buff *skb, struct genl_info *info)
{
    struct melodi_node_id node_id;
    struct melodi_node_id previous_node_id;
    const struct melodi_node_id *previous = NULL;
    struct net_device *dev;
    key_ref_t key_ref;
    struct key *key;
    const struct user_key_payload *key_payload;
    int error;

    if (!netlink_capable(skb, CAP_NET_ADMIN))
        return -EPERM;
    if (!info->attrs[MELODI_A_IFINDEX] ||
        !info->attrs[MELODI_A_NODE_ID] ||
        !info->attrs[MELODI_A_KEY_SERIAL] ||
        !info->attrs[MELODI_A_GENERATION])
        return -EINVAL;
    memcpy(&node_id, nla_data(info->attrs[MELODI_A_NODE_ID]),
           sizeof(node_id));
    if (!nla_get_u32(info->attrs[MELODI_A_GENERATION]))
        return -EINVAL;
    if (info->attrs[MELODI_A_PREVIOUS_NODE_ID]) {
        memcpy(&previous_node_id,
               nla_data(info->attrs[MELODI_A_PREVIOUS_NODE_ID]),
               sizeof(previous_node_id));
        if (!melodi_node_id_valid(&previous_node_id))
            return -EINVAL;
        previous = &previous_node_id;
    }
    key_ref = lookup_user_key(nla_get_u32(info->attrs[MELODI_A_KEY_SERIAL]),
                              KEY_LOOKUP_PARTIAL, KEY_NEED_READ);
    if (IS_ERR(key_ref))
        return PTR_ERR(key_ref);
    key = key_ref_to_ptr(key_ref);
    error = key_validate(key);
    if (!error && key->type != &key_type_user)
        error = -EKEYREJECTED;
    if (!error) {
        down_read(&key->sem);
        key_payload = user_key_payload_locked(key);
        if (!key_payload || key_payload->datalen != MELODI_NODE_KEY_SIZE)
            error = -EKEYREJECTED;
        up_read(&key->sem);
    }
    if (!error)
        error = melodi_identity_key_matches(key, &node_id);
    if (error) {
        key_ref_put(key_ref);
        return error;
    }
    dev = melodi_device_get(genl_info_net(info),
                            nla_get_u32(info->attrs[MELODI_A_IFINDEX]));
    if (!dev) {
        key_ref_put(key_ref);
        return -ENODEV;
    }
    error = melodi_device_set_identity(
        dev, &node_id, key,
        nla_get_u32(info->attrs[MELODI_A_GENERATION]), previous);
    dev_put(dev);
    key_ref_put(key_ref);
    return error;
}

static int melodi_identity_get(struct sk_buff *skb, struct genl_info *info)
{
    struct melodi_node_id node_id;
    u32 generation;
    struct net_device *dev;
    struct sk_buff *reply;
    void *header;
    int error;

    if (!info->attrs[MELODI_A_IFINDEX])
        return -EINVAL;
    dev = melodi_device_get(genl_info_net(info),
                            nla_get_u32(info->attrs[MELODI_A_IFINDEX]));
    if (!dev)
        return -ENODEV;
    if (!melodi_device_identity(dev, &node_id, &generation)) {
        dev_put(dev);
        return -ENOKEY;
    }
    dev_put(dev);
    reply = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!reply)
        return -ENOMEM;
    header = genlmsg_put_reply(reply, info, &melodi_genl_family, 0,
                               MELODI_CMD_IDENTITY_GET_PUBLIC);
    if (!header) {
        nlmsg_free(reply);
        return -EMSGSIZE;
    }
    error = nla_put(reply, MELODI_A_NODE_ID, sizeof(node_id), &node_id) ?:
            nla_put_u32(reply, MELODI_A_GENERATION, generation);
    if (error) {
        nlmsg_free(reply);
        return error;
    }
    genlmsg_end(reply, header);
    return genlmsg_reply(reply, info);
}

static int melodi_link_get(struct sk_buff *skb, struct genl_info *info)
{
    struct melodi_device *melodi;
    struct net_device *dev;
    struct sk_buff *reply;
    enum melodi_link_state state;
    enum melodi_link_failure failure;
    char radio_serial[MELODI_RADIO_SERIAL_MAX + 1];
    char bus_info[MELODI_BUS_INFO_MAX + 1] = {};
    struct melodi_link_info link;
    u32 frame_pace_us = 0;
    int link_error;
    void *header;

    if (!info->attrs[MELODI_A_IFINDEX])
        return -EINVAL;
    dev = melodi_device_get(genl_info_net(info),
                            nla_get_u32(info->attrs[MELODI_A_IFINDEX]));
    if (!dev)
        return -ENODEV;
    melodi = netdev_priv(dev);
    mutex_lock(&melodi->lock);
    state = melodi->link_state;
    failure = melodi->link_failure;
    link_error = melodi->link_error;
    strscpy(radio_serial, melodi->radio_serial, sizeof(radio_serial));
    mutex_unlock(&melodi->lock);
    if (!melodi_core_link_info(dev, &link)) {
        strscpy(bus_info, link.bus_info, sizeof(bus_info));
        frame_pace_us = link.frame_pace_us;
    }
    dev_put(dev);
    reply = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!reply)
        return -ENOMEM;
    header = genlmsg_put_reply(reply, info, &melodi_genl_family, 0,
                               MELODI_CMD_LINK_GET);
    if (!header) {
        nlmsg_free(reply);
        return -EMSGSIZE;
    }
    if (nla_put_u8(reply, MELODI_A_LINK_STATE, state) ||
        nla_put_u16(reply, MELODI_A_LINK_FAILURE, failure) ||
        nla_put_s32(reply, MELODI_A_LINK_ERROR, link_error) ||
        (radio_serial[0] &&
         nla_put_string(reply, MELODI_A_RADIO_SERIAL, radio_serial)) ||
        (bus_info[0] && nla_put_string(reply, MELODI_A_BUS_INFO, bus_info)) ||
        (frame_pace_us &&
         nla_put_u32(reply, MELODI_A_FRAME_PACE_US, frame_pace_us))) {
        nlmsg_free(reply);
        return -EMSGSIZE;
    }
    genlmsg_end(reply, header);
    return genlmsg_reply(reply, info);
}

static int melodi_link_set(struct sk_buff *skb, struct genl_info *info)
{
    struct net_device *dev;
    int error;

    if (!netlink_capable(skb, CAP_NET_ADMIN))
        return -EPERM;
    if (!info->attrs[MELODI_A_IFINDEX] ||
        !info->attrs[MELODI_A_RADIO_SERIAL])
        return -EINVAL;
    dev = melodi_device_get(genl_info_net(info),
                            nla_get_u32(info->attrs[MELODI_A_IFINDEX]));
    if (!dev)
        return -ENODEV;
    error = melodi_set_transport_selector(
        dev, nla_data(info->attrs[MELODI_A_RADIO_SERIAL]));
    dev_put(dev);
    return error;
}

static int melodi_peer_policy_update(struct sk_buff *skb,
                                     struct genl_info *info,
                                     enum melodi_peer_state state)
{
    struct melodi_node_id node_id;
    struct net_device *dev;
    int error;

    if (!netlink_capable(skb, CAP_NET_ADMIN))
        return -EPERM;
    if (!info->attrs[MELODI_A_IFINDEX] ||
        !info->attrs[MELODI_A_NODE_ID])
        return -EINVAL;
    memcpy(&node_id, nla_data(info->attrs[MELODI_A_NODE_ID]),
           sizeof(node_id));
    dev = melodi_device_get(genl_info_net(info),
                            nla_get_u32(info->attrs[MELODI_A_IFINDEX]));
    if (!dev)
        return -ENODEV;
    error = melodi_policy_set_peer(dev, &node_id, state);
    dev_put(dev);
    return error;
}

static int melodi_peer_trust(struct sk_buff *skb, struct genl_info *info)
{
    return melodi_peer_policy_update(skb, info, MELODI_PEER_TRUSTED);
}

static int melodi_peer_block(struct sk_buff *skb, struct genl_info *info)
{
    return melodi_peer_policy_update(skb, info, MELODI_PEER_BLOCKED);
}

static int melodi_peer_clear(struct sk_buff *skb, struct genl_info *info)
{
    struct melodi_node_id node_id;
    struct net_device *dev;
    int error;

    if (!netlink_capable(skb, CAP_NET_ADMIN))
        return -EPERM;
    if (!info->attrs[MELODI_A_IFINDEX] ||
        !info->attrs[MELODI_A_NODE_ID])
        return -EINVAL;
    memcpy(&node_id, nla_data(info->attrs[MELODI_A_NODE_ID]),
           sizeof(node_id));
    dev = melodi_device_get(genl_info_net(info),
                            nla_get_u32(info->attrs[MELODI_A_IFINDEX]));
    if (!dev)
        return -ENODEV;
    error = melodi_policy_clear_peer(dev, &node_id);
    dev_put(dev);
    return error;
}

static int melodi_peer_reverify(struct sk_buff *skb, struct genl_info *info)
{
    struct melodi_node_id node_id;
    struct net_device *dev;
    int error;

    if (!netlink_capable(skb, CAP_NET_ADMIN))
        return -EPERM;
    if (!info->attrs[MELODI_A_IFINDEX] ||
        !info->attrs[MELODI_A_NODE_ID])
        return -EINVAL;
    memcpy(&node_id, nla_data(info->attrs[MELODI_A_NODE_ID]),
           sizeof(node_id));
    dev = melodi_device_get(genl_info_net(info),
                            nla_get_u32(info->attrs[MELODI_A_IFINDEX]));
    if (!dev)
        return -ENODEV;
    error = melodi_policy_reverify_peer(dev, &node_id);
    dev_put(dev);
    return error;
}

static int melodi_peer_dump(struct sk_buff *message,
                            struct netlink_callback *callback)
{
    const struct genl_info *info = genl_info_dump(callback);
    struct melodi_device *melodi;
    struct net_device *dev;
    unsigned long index;
    void *header;
    int error;

    if (!info->attrs[MELODI_A_IFINDEX])
        return -EINVAL;
    dev = melodi_device_get(genl_info_net(info),
                            nla_get_u32(info->attrs[MELODI_A_IFINDEX]));
    if (!dev)
        return -ENODEV;
    melodi = netdev_priv(dev);
    mutex_lock(&melodi->lock);
    for (index = callback->args[0]; index < MELODI_PEER_LIMIT; index++) {
        struct melodi_peer *peer = &melodi->peers[index];
        enum melodi_peer_state state;
        enum melodi_peer_policy policy;
        unsigned long remaining;
        u32 expiry_ms;

        if (!peer->authenticated)
            continue;
        header = genlmsg_put(message, NETLINK_CB(callback->skb).portid,
                             callback->nlh->nlmsg_seq,
                             &melodi_genl_family, NLM_F_MULTI,
                             MELODI_CMD_PEER_DUMP);
        if (!header)
            break;
        state = melodi_policy_peer_state_locked(melodi, peer);
        policy = melodi_policy_peer_policy_locked(melodi, peer);
        remaining = time_after(peer->expires, jiffies) ?
                    peer->expires - jiffies : 0;
        expiry_ms = min_t(u64, jiffies_to_msecs(remaining), U32_MAX);
        error = nla_put_u32(message, MELODI_A_IFINDEX, dev->ifindex);
        if (!error)
            error = nla_put(message, MELODI_A_NODE_ID,
                            sizeof(peer->node_id), &peer->node_id);
        if (!error)
            error = nla_put_u32(message, MELODI_A_PEER_NATIVE_LOCATOR,
                                peer->native_locator);
        if (!error)
            error = nla_put_u32(message, MELODI_A_COLLISION_ROUND,
                                peer->collision_round);
        if (!error)
            error = nla_put_u32(message, MELODI_A_GENERATION,
                                peer->generation);
        if (!error)
            error = nla_put_u8(message, MELODI_A_PEER_STATE, state);
        if (!error)
            error = nla_put_u32(message, MELODI_A_PEER_EXPIRY_MS,
                                expiry_ms);
        if (!error)
            error = nla_put_u32(message, MELODI_A_PEER_CAPABILITIES,
                                peer->capabilities);
        if (!error)
            error = nla_put_s16(message, MELODI_A_PEER_RSSI, peer->rssi);
        if (!error)
            error = nla_put_s16(message, MELODI_A_PEER_SNR, peer->snr);
        if (!error)
            error = nla_put_u8(message, MELODI_A_PEER_HOPS, peer->hops);
        if (!error)
            error = nla_put_u64_64bit(message,
                                      MELODI_A_PEER_LAST_SEEN_NS,
                                      peer->last_seen_ns,
                                      MELODI_A_UNSPEC);
        if (!error)
            error = nla_put_u8(message, MELODI_A_PEER_POLICY, policy);
        if (error) {
            genlmsg_cancel(message, header);
            break;
        }
        genlmsg_end(message, header);
        callback->args[0] = index + 1;
    }
    mutex_unlock(&melodi->lock);
    dev_put(dev);
    return message->len;
}

static int melodi_policy_get(struct sk_buff *skb, struct genl_info *info)
{
    struct melodi_device *melodi;
    struct net_device *dev;
    struct sk_buff *reply;
    enum melodi_policy_mode mode;
    void *header;
    int error;

    if (!info->attrs[MELODI_A_IFINDEX])
        return -EINVAL;
    dev = melodi_device_get(genl_info_net(info),
                            nla_get_u32(info->attrs[MELODI_A_IFINDEX]));
    if (!dev)
        return -ENODEV;
    melodi = netdev_priv(dev);
    mutex_lock(&melodi->lock);
    mode = melodi->policy_mode;
    mutex_unlock(&melodi->lock);
    dev_put(dev);
    reply = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!reply)
        return -ENOMEM;
    header = genlmsg_put_reply(reply, info, &melodi_genl_family, 0,
                               MELODI_CMD_POLICY_GET);
    if (!header) {
        nlmsg_free(reply);
        return -EMSGSIZE;
    }
    error = nla_put_u8(reply, MELODI_A_POLICY_MODE, mode);
    if (error) {
        nlmsg_free(reply);
        return error;
    }
    genlmsg_end(reply, header);
    return genlmsg_reply(reply, info);
}

static int melodi_policy_set(struct sk_buff *skb, struct genl_info *info)
{
    struct net_device *dev;
    enum melodi_policy_mode mode;
    int error;

    if (!netlink_capable(skb, CAP_NET_ADMIN))
        return -EPERM;
    if (!info->attrs[MELODI_A_IFINDEX])
        return -EINVAL;
    if (!!info->attrs[MELODI_A_POLICY_SERVICE] !=
            !!info->attrs[MELODI_A_POLICY_ACTION] ||
        (info->attrs[MELODI_A_POLICY_RESET] &&
         (info->attrs[MELODI_A_POLICY_MODE] ||
          info->attrs[MELODI_A_POLICY_SERVICE] ||
          info->attrs[MELODI_A_POLICY_BROADCAST])) ||
        (info->attrs[MELODI_A_POLICY_MODE] &&
         (info->attrs[MELODI_A_POLICY_SERVICE] ||
          info->attrs[MELODI_A_POLICY_BROADCAST])) ||
        (info->attrs[MELODI_A_POLICY_BROADCAST] &&
         info->attrs[MELODI_A_POLICY_SERVICE]) ||
        (!info->attrs[MELODI_A_POLICY_MODE] &&
         !info->attrs[MELODI_A_POLICY_SERVICE] &&
         !info->attrs[MELODI_A_POLICY_BROADCAST] &&
         !info->attrs[MELODI_A_POLICY_RESET]))
        return -EINVAL;
    dev = melodi_device_get(genl_info_net(info),
                            nla_get_u32(info->attrs[MELODI_A_IFINDEX]));
    if (!dev)
        return -ENODEV;
    if (info->attrs[MELODI_A_POLICY_RESET]) {
        int error = melodi_policy_reset(dev);

        dev_put(dev);
        return error;
    }
    if (info->attrs[MELODI_A_POLICY_SERVICE] &&
        info->attrs[MELODI_A_POLICY_ACTION]) {
        int error = melodi_policy_set_service(
            dev, nla_get_u16(info->attrs[MELODI_A_POLICY_SERVICE]),
            nla_get_u8(info->attrs[MELODI_A_POLICY_ACTION]));

        dev_put(dev);
        return error;
    }
    if (info->attrs[MELODI_A_POLICY_BROADCAST]) {
        int error = melodi_policy_set_broadcast(
            dev, nla_get_u8(info->attrs[MELODI_A_POLICY_BROADCAST]));

        dev_put(dev);
        return error;
    }
    if (!info->attrs[MELODI_A_POLICY_MODE]) {
        dev_put(dev);
        return -EINVAL;
    }
    mode = nla_get_u8(info->attrs[MELODI_A_POLICY_MODE]);
    error = melodi_policy_set_mode(dev, mode);
    dev_put(dev);
    return error;
}

static int melodi_discover(struct sk_buff *skb, struct genl_info *info)
{
    struct net_device *dev;
    int error;

    if (!netlink_capable(skb, CAP_NET_ADMIN))
        return -EPERM;
    if (!info->attrs[MELODI_A_IFINDEX])
        return -EINVAL;
    dev = melodi_device_get(genl_info_net(info),
                            nla_get_u32(info->attrs[MELODI_A_IFINDEX]));
    if (!dev)
        return -ENODEV;
    error = melodi_discovery_probe(dev);
    dev_put(dev);
    return error;
}

static int melodi_stats_get(struct sk_buff *skb, struct genl_info *info)
{
    struct melodi_stats_snapshot snapshot;
    struct net_device *dev;
    struct nlattr *nested;
    struct sk_buff *reply;
    unsigned int index;
    void *header;

    if (!info->attrs[MELODI_A_IFINDEX])
        return -EINVAL;
    dev = melodi_device_get(genl_info_net(info),
                            nla_get_u32(info->attrs[MELODI_A_IFINDEX]));
    if (!dev)
        return -ENODEV;
    melodi_stats_read(dev, &snapshot);
    dev_put(dev);
    reply = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!reply)
        return -ENOMEM;
    header = genlmsg_put_reply(reply, info, &melodi_genl_family, 0,
                               MELODI_CMD_STATS_GET);
    if (!header)
        goto size_error;
    nested = nla_nest_start(reply, MELODI_A_STATS);
    if (!nested)
        goto size_error;
    for (index = 1; index <= MELODI_STAT_A_MAX; index++)
        if (nla_put_u64_64bit(reply, index, snapshot.values[index],
                              MELODI_STAT_A_UNSPEC))
            goto size_error;
    nla_nest_end(reply, nested);
    genlmsg_end(reply, header);
    return genlmsg_reply(reply, info);
size_error:
    nlmsg_free(reply);
    return -EMSGSIZE;
}

static int melodi_monitor_bind(struct sk_buff *skb, struct genl_info *info)
{
    struct melodi_monitor *monitor;
    struct melodi_monitor *existing;
    struct net_device *dev;
    struct net *net = genl_info_net(info);
    int ifindex;

    if (!netlink_capable(skb, CAP_NET_RAW))
        return -EPERM;
    if (!info->attrs[MELODI_A_IFINDEX])
        return -EINVAL;
    ifindex = nla_get_u32(info->attrs[MELODI_A_IFINDEX]);
    dev = melodi_device_get(net, ifindex);
    if (!dev)
        return -ENODEV;
    monitor = kzalloc(sizeof(*monitor), GFP_KERNEL);
    if (!monitor) {
        dev_put(dev);
        return -ENOMEM;
    }
    monitor->net = get_net(net);
    monitor->dev = dev;
    monitor->portid = info->snd_portid;
    mutex_lock(&melodi_bindings_lock);
    list_for_each_entry(existing, &melodi_monitors, node)
        if (existing->net == net && existing->portid == info->snd_portid) {
            mutex_unlock(&melodi_bindings_lock);
            melodi_monitor_free(monitor);
            return -EALREADY;
        }
    list_add_tail(&monitor->node, &melodi_monitors);
    __module_get(THIS_MODULE);
    monitor->module_held = true;
    mutex_unlock(&melodi_bindings_lock);
    return 0;
}

static const struct genl_ops melodi_ops[] = {
    { .cmd = MELODI_CMD_BIND, .policy = melodi_policy,
      .maxattr = MELODI_A_MAX, .doit = melodi_bind },
    { .cmd = MELODI_CMD_UNBIND, .policy = melodi_policy,
      .maxattr = MELODI_A_MAX, .doit = melodi_unbind },
    { .cmd = MELODI_CMD_SEND, .policy = melodi_policy,
      .maxattr = MELODI_A_MAX, .doit = melodi_send },
    { .cmd = MELODI_CMD_GET_BINDING, .policy = melodi_policy,
      .maxattr = MELODI_A_MAX, .doit = melodi_get_binding },
    { .cmd = MELODI_CMD_LINK_GET, .policy = melodi_policy,
      .maxattr = MELODI_A_MAX, .doit = melodi_link_get },
    { .cmd = MELODI_CMD_LINK_SET, .policy = melodi_policy,
      .maxattr = MELODI_A_MAX, .doit = melodi_link_set },
    { .cmd = MELODI_CMD_IDENTITY_LOAD, .policy = melodi_policy,
      .maxattr = MELODI_A_MAX, .doit = melodi_identity_load },
    { .cmd = MELODI_CMD_IDENTITY_GET_PUBLIC, .policy = melodi_policy,
      .maxattr = MELODI_A_MAX, .doit = melodi_identity_get },
    { .cmd = MELODI_CMD_PEER_DUMP, .policy = melodi_policy,
      .maxattr = MELODI_A_MAX, .dumpit = melodi_peer_dump },
    { .cmd = MELODI_CMD_PEER_TRUST, .policy = melodi_policy,
      .maxattr = MELODI_A_MAX, .doit = melodi_peer_trust },
    { .cmd = MELODI_CMD_PEER_BLOCK, .policy = melodi_policy,
      .maxattr = MELODI_A_MAX, .doit = melodi_peer_block },
    { .cmd = MELODI_CMD_PEER_CLEAR, .policy = melodi_policy,
      .maxattr = MELODI_A_MAX, .doit = melodi_peer_clear },
    { .cmd = MELODI_CMD_PEER_REVERIFY, .policy = melodi_policy,
      .maxattr = MELODI_A_MAX, .doit = melodi_peer_reverify },
    { .cmd = MELODI_CMD_POLICY_GET, .policy = melodi_policy,
      .maxattr = MELODI_A_MAX, .doit = melodi_policy_get },
    { .cmd = MELODI_CMD_POLICY_SET, .policy = melodi_policy,
      .maxattr = MELODI_A_MAX, .doit = melodi_policy_set },
    { .cmd = MELODI_CMD_DISCOVER, .policy = melodi_policy,
      .maxattr = MELODI_A_MAX, .doit = melodi_discover },
    { .cmd = MELODI_CMD_STATS_GET, .policy = melodi_policy,
      .maxattr = MELODI_A_MAX, .doit = melodi_stats_get },
    { .cmd = MELODI_CMD_MONITOR_BIND, .policy = melodi_policy,
      .maxattr = MELODI_A_MAX, .doit = melodi_monitor_bind },
};

struct genl_family melodi_genl_family = {
    .name = MELODI_GENL_NAME,
    .version = MELODI_GENL_VERSION,
    .maxattr = MELODI_A_MAX,
    .netnsok = true,
    .parallel_ops = false,
    .pre_doit = melodi_pre_doit,
    .module = THIS_MODULE,
    .ops = melodi_ops,
    .n_ops = ARRAY_SIZE(melodi_ops),
};

static int melodi_netlink_release(struct notifier_block *block,
                                  unsigned long event, void *data)
{
    struct netlink_notify *notify = data;
    struct melodi_binding *binding;
    struct melodi_binding *next;
    struct melodi_monitor *monitor;
    struct melodi_monitor *monitor_next;

    if (event != NETLINK_URELEASE || notify->protocol != NETLINK_GENERIC)
        return NOTIFY_DONE;
    mutex_lock(&melodi_bindings_lock);
    list_for_each_entry_safe(binding, next, &melodi_bindings, node) {
        if (binding->net == notify->net && binding->portid == notify->portid) {
            list_del(&binding->node);
            melodi_binding_free(binding);
        }
    }
    list_for_each_entry_safe(monitor, monitor_next, &melodi_monitors, node) {
        if (monitor->net == notify->net && monitor->portid == notify->portid) {
            list_del(&monitor->node);
            melodi_monitor_free(monitor);
        }
    }
    mutex_unlock(&melodi_bindings_lock);
    return NOTIFY_OK;
}

static struct notifier_block melodi_netlink_notifier = {
    .notifier_call = melodi_netlink_release,
};

static int melodi_netdevice_event(struct notifier_block *block,
                                  unsigned long event, void *data)
{
    struct net_device *dev = netdev_notifier_info_to_dev(data);

    (void)block;
    if (event == NETDEV_UNREGISTER && melodi_device_is(dev)) {
        melodi_netlink_interface_removed(dev);
        if (READ_ONCE(dev->moving_ns))
            melodi_namespace_reset(dev);
    }
    return NOTIFY_DONE;
}

static struct notifier_block melodi_netdevice_notifier = {
    .notifier_call = melodi_netdevice_event,
};

void melodi_netlink_interface_removed(struct net_device *dev)
{
    struct melodi_binding *binding;
    struct melodi_binding *next;
    struct melodi_monitor *monitor;
    struct melodi_monitor *monitor_next;

    mutex_lock(&melodi_bindings_lock);
    list_for_each_entry_safe(binding, next, &melodi_bindings, node) {
        if (binding->dev == dev) {
            melodi_binding_error(binding, -ENODEV, false, 0);
            list_del(&binding->node);
            melodi_binding_free(binding);
        }
    }
    list_for_each_entry_safe(monitor, monitor_next, &melodi_monitors, node) {
        if (monitor->dev == dev) {
            list_del(&monitor->node);
            melodi_monitor_free(monitor);
        }
    }
    mutex_unlock(&melodi_bindings_lock);
}

void melodi_netlink_delivery_error(struct net_device *dev,
                                   u32 binding_portid,
                                   u64 binding_generation,
                                   u16 source_service, u64 cookie, int error)
{
    struct melodi_binding *binding;

    if (!dev || !error)
        return;
    mutex_lock(&melodi_bindings_lock);
    binding = melodi_binding_by_token(dev, binding_portid,
                                      binding_generation, source_service);
    if (binding)
        melodi_binding_error(binding, error, true, cookie);
    mutex_unlock(&melodi_bindings_lock);
}

void melodi_netlink_link_error(struct net_device *dev, int error)
{
    struct melodi_binding *binding;

    if (!dev || !error)
        return;
    mutex_lock(&melodi_bindings_lock);
    list_for_each_entry(binding, &melodi_bindings, node)
        if (binding->dev == dev)
            melodi_binding_error(binding, error, false, 0);
    mutex_unlock(&melodi_bindings_lock);
}

int melodi_netlink_receive(struct net_device *dev,
                           const struct melodi_node_id *source,
                           u16 source_service, u16 destination_service,
                           const void *payload, size_t length,
                           const struct melodi_rx_meta *meta)
{
    struct melodi_device *melodi;
    struct melodi_binding *binding;
    struct nlattr *nested;
    struct sk_buff *message;
    struct net *net;
    u64 timestamp;
    u32 portid;
    void *header;
    int error;

    if (!dev || !source || (!payload && length) ||
        length > MELODI_MESSAGE_MTU || !meta)
        return -EINVAL;
    melodi = netdev_priv(dev);
    mutex_lock(&melodi_bindings_lock);
    binding = melodi_binding_by_service(dev, destination_service);
    if (!binding) {
        mutex_unlock(&melodi_bindings_lock);
        atomic64_inc(&melodi->app_delivery_drops);
        return -ECONNREFUSED;
    }
    net = get_net(binding->net);
    portid = binding->portid;
    message = genlmsg_new(nla_total_size(sizeof(*source)) +
                          nla_total_size(sizeof(source_service)) +
                          nla_total_size(sizeof(destination_service)) +
                          nla_total_size(length) + 128, GFP_KERNEL);
    if (!message) {
        error = -ENOMEM;
        goto put_net;
    }
    header = genlmsg_put(message, 0, 0, &melodi_genl_family, 0,
                         MELODI_CMD_RECV);
    if (!header) {
        error = -EMSGSIZE;
        goto free;
    }
    error = nla_put(message, MELODI_A_SOURCE_NODE, sizeof(*source), source);
    if (!error)
        error = nla_put_u16(message, MELODI_A_SOURCE_SERVICE,
                            source_service);
    if (!error)
        error = nla_put_u16(message, MELODI_A_LOCAL_SERVICE,
                            destination_service);
    if (!error)
        error = nla_put(message, MELODI_A_PAYLOAD, length, payload);
    if (error)
        goto free;
    nested = nla_nest_start(message, MELODI_A_RX_META);
    if (!nested) {
        error = -EMSGSIZE;
        goto free;
    }
    timestamp = meta->timestamp_ns ? meta->timestamp_ns : ktime_get_ns();
    if (nla_put_u8(message, MELODI_RX_A_AUTHENTICATED,
                   meta->authenticated) ||
        nla_put_u16(message, MELODI_RX_A_DUPLICATES, meta->duplicates) ||
        nla_put_u8(message, MELODI_RX_A_HOPS, meta->hops) ||
        nla_put_s16(message, MELODI_RX_A_RSSI, meta->rssi) ||
        nla_put_s16(message, MELODI_RX_A_SNR, meta->snr) ||
        nla_put_u64_64bit(message, MELODI_RX_A_TIMESTAMP_NS, timestamp,
                          MELODI_RX_A_UNSPEC) ||
        nla_put_u8(message, MELODI_RX_A_RETRANSMISSIONS,
                   meta->retransmissions)) {
        error = -EMSGSIZE;
        goto free;
    }
    nla_nest_end(message, nested);
    genlmsg_end(message, header);
    error = genlmsg_unicast(net, message, portid);
    if (error)
        atomic64_inc(&melodi->app_delivery_drops);
    mutex_unlock(&melodi_bindings_lock);
    put_net(net);
    return error;
free:
    nlmsg_free(message);
put_net:
    mutex_unlock(&melodi_bindings_lock);
    put_net(net);
    atomic64_inc(&melodi->app_delivery_drops);
    return error;
}

void melodi_netlink_monitor_frame(struct net_device *dev, u8 direction,
                                  const void *frame, size_t length,
                                  const struct melodi_rx_meta *meta)
{
    struct melodi_device *melodi;
    struct melodi_monitor *monitor;
    struct nlattr *nested;
    struct sk_buff *message;
    u64 timestamp;
    void *header;
    int error;

    if (!dev || !frame || length < MELODI_FRAME_HEADER_MIN ||
        length > MELODI_FRAME_MTU_MAX || direction > MELODI_MONITOR_TX ||
        (direction == MELODI_MONITOR_RX && !meta))
        return;
    melodi = netdev_priv(dev);
    mutex_lock(&melodi_bindings_lock);
    list_for_each_entry(monitor, &melodi_monitors, node) {
        if (monitor->dev != dev || monitor->net != dev_net(dev))
            continue;
        message = genlmsg_new(nla_total_size(length) + 192, GFP_KERNEL);
        if (!message) {
            atomic64_inc(&melodi->monitor_drops);
            continue;
        }
        header = genlmsg_put(message, 0, 0, &melodi_genl_family, 0,
                             MELODI_CMD_MONITOR_FRAME);
        if (!header ||
            nla_put_u32(message, MELODI_A_IFINDEX, dev->ifindex) ||
            nla_put_u8(message, MELODI_A_MONITOR_DIRECTION, direction) ||
            nla_put(message, MELODI_A_FRAME, length, frame))
            goto frame_error;
        if (direction == MELODI_MONITOR_RX) {
            nested = nla_nest_start(message, MELODI_A_RX_META);
            if (!nested)
                goto frame_error;
            timestamp = meta->timestamp_ns ? meta->timestamp_ns :
                        ktime_get_ns();
            if (nla_put_u8(message, MELODI_RX_A_AUTHENTICATED,
                           meta->authenticated) ||
                nla_put_u16(message, MELODI_RX_A_DUPLICATES,
                            meta->duplicates) ||
                nla_put_u8(message, MELODI_RX_A_HOPS, meta->hops) ||
                nla_put_s16(message, MELODI_RX_A_RSSI, meta->rssi) ||
                nla_put_s16(message, MELODI_RX_A_SNR, meta->snr) ||
                nla_put_u64_64bit(message, MELODI_RX_A_TIMESTAMP_NS,
                                  timestamp, MELODI_RX_A_UNSPEC) ||
                nla_put_u8(message, MELODI_RX_A_RETRANSMISSIONS,
                           meta->retransmissions))
                goto frame_error;
            nla_nest_end(message, nested);
        }
        genlmsg_end(message, header);
        error = genlmsg_unicast(monitor->net, message, monitor->portid);
        if (error)
            atomic64_inc(&melodi->monitor_drops);
        continue;
frame_error:
        nlmsg_free(message);
        atomic64_inc(&melodi->monitor_drops);
    }
    mutex_unlock(&melodi_bindings_lock);
}

int melodi_netlink_register(void)
{
    int error;

    error = netlink_register_notifier(&melodi_netlink_notifier);
    if (error)
        return error;
    error = register_netdevice_notifier(&melodi_netdevice_notifier);
    if (error) {
        netlink_unregister_notifier(&melodi_netlink_notifier);
        return error;
    }
    error = genl_register_family(&melodi_genl_family);
    if (error) {
        unregister_netdevice_notifier(&melodi_netdevice_notifier);
        netlink_unregister_notifier(&melodi_netlink_notifier);
    }
    return error;
}

void melodi_netlink_unregister(void)
{
    struct melodi_binding *binding;
    struct melodi_binding *next;
    struct melodi_monitor *monitor;
    struct melodi_monitor *monitor_next;

    genl_unregister_family(&melodi_genl_family);
    unregister_netdevice_notifier(&melodi_netdevice_notifier);
    netlink_unregister_notifier(&melodi_netlink_notifier);
    mutex_lock(&melodi_bindings_lock);
    list_for_each_entry_safe(binding, next, &melodi_bindings, node) {
        list_del(&binding->node);
        melodi_binding_free(binding);
    }
    list_for_each_entry_safe(monitor, monitor_next, &melodi_monitors, node) {
        list_del(&monitor->node);
        melodi_monitor_free(monitor);
    }
    mutex_unlock(&melodi_bindings_lock);
}
