/* SPDX-License-Identifier: GPL-2.0-only */
#include "genl.h"

#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <string.h>

#define MELODI_ALIGNTO 4U
#define MELODI_ALIGN(value) (((value) + MELODI_ALIGNTO - 1U) & ~(MELODI_ALIGNTO - 1U))

static int melodi_command_valid(uint8_t command)
{
    return (command >= MELODI_CMD_BIND &&
            command <= MELODI_CMD_GET_BINDING) ||
           (command >= MELODI_CMD_LINK_GET &&
            command <= MELODI_CMD_MONITOR_FRAME);
}

static int melodi_attribute_width(uint16_t type, uint16_t length)
{
    switch (type) {
    case MELODI_A_IFINDEX:
    case MELODI_A_FLAGS:
    case MELODI_A_TTL_MS:
    case MELODI_A_KEY_SERIAL:
    case MELODI_A_PEER_NATIVE_LOCATOR:
    case MELODI_A_COLLISION_ROUND:
    case MELODI_A_GENERATION:
    case MELODI_A_LINK_ERROR:
    case MELODI_A_PEER_EXPIRY_MS:
    case MELODI_A_PEER_CAPABILITIES:
    case MELODI_A_FRAME_PACE_US:
        return length == sizeof(uint32_t);
    case MELODI_A_LOCAL_SERVICE:
    case MELODI_A_DEST_SERVICE:
    case MELODI_A_SOURCE_SERVICE:
    case MELODI_A_LINK_FAILURE:
    case MELODI_A_POLICY_SERVICE:
    case MELODI_A_PEER_RSSI:
    case MELODI_A_PEER_SNR:
        return length == sizeof(uint16_t);
    case MELODI_A_DEST_NODE:
    case MELODI_A_SOURCE_NODE:
    case MELODI_A_NODE_ID:
    case MELODI_A_PREVIOUS_NODE_ID:
        return length == MELODI_NODE_ID_SIZE;
    case MELODI_A_COOKIE:
    case MELODI_A_PEER_LAST_SEEN_NS:
        return length == sizeof(uint64_t);
    case MELODI_A_PRIORITY:
    case MELODI_A_LINK_STATE:
    case MELODI_A_PEER_STATE:
    case MELODI_A_POLICY_MODE:
    case MELODI_A_POLICY_ACTION:
    case MELODI_A_POLICY_BROADCAST:
    case MELODI_A_POLICY_RESET:
    case MELODI_A_PEER_HOPS:
    case MELODI_A_PEER_POLICY:
    case MELODI_A_MONITOR_DIRECTION:
        return length == sizeof(uint8_t);
    case MELODI_A_PAYLOAD:
        return length <= MELODI_MESSAGE_MTU;
    case MELODI_A_RADIO_SERIAL:
        return length >= 2 && length <= MELODI_RADIO_SERIAL_MAX + 1;
    case MELODI_A_BUS_INFO:
        return length >= 2 && length <= MELODI_BUS_INFO_MAX + 1;
    case MELODI_A_RX_META:
    case MELODI_A_ERROR:
    case MELODI_A_STATS:
        return length >= sizeof(struct nlattr);
    case MELODI_A_FRAME:
        return length >= MELODI_FRAME_HEADER_MIN &&
               length <= MELODI_FRAME_MTU_MAX;
    default:
        return 0;
    }
}

static int melodi_has(const struct melodi_genl_message *message, uint16_t type)
{
    return message->attributes[type] != NULL;
}

static uint64_t melodi_present(const struct melodi_genl_message *message)
{
    uint64_t present = 0;
    uint16_t type;

    for (type = 1; type <= MELODI_A_MAX; type++)
        if (melodi_has(message, type))
            present |= UINT64_C(1) << type;
    return present;
}

static int melodi_validate_bind(const struct melodi_genl_message *message)
{
    uint16_t service;

    if (!melodi_has(message, MELODI_A_IFINDEX) ||
        !melodi_has(message, MELODI_A_LOCAL_SERVICE))
        return -EINVAL;
    memcpy(&service, message->attributes[MELODI_A_LOCAL_SERVICE], sizeof(service));
    if (service == MELODI_SERVICE_CONTROL || service == MELODI_SERVICE_ECHO)
        return -EINVAL;
    return 0;
}

static int melodi_validate_send(const struct melodi_genl_message *message)
{
    uint32_t flags = 0;
    uint32_t ttl_ms;
    uint8_t priority;

    if (!melodi_has(message, MELODI_A_DEST_SERVICE) ||
        !melodi_has(message, MELODI_A_PAYLOAD))
        return -EINVAL;
    if (melodi_has(message, MELODI_A_FLAGS))
        memcpy(&flags, message->attributes[MELODI_A_FLAGS], sizeof(flags));
    if (flags & ~MELODI_F_ALL)
        return -EINVAL;
    if (!!(flags & MELODI_F_BROADCAST) ==
        !!melodi_has(message, MELODI_A_DEST_NODE))
        return -EINVAL;
    if (flags & MELODI_F_BROADCAST) {
        if (flags & (MELODI_F_RELIABLE | MELODI_F_ORDERED))
            return -EINVAL;
        if (message->lengths[MELODI_A_PAYLOAD] > MELODI_BROADCAST_MTU)
            return -EMSGSIZE;
    }
    if (melodi_has(message, MELODI_A_PRIORITY)) {
        memcpy(&priority, message->attributes[MELODI_A_PRIORITY], sizeof(priority));
        if (priority > MELODI_PRIORITY_MAX)
            return -EINVAL;
    }
    if (melodi_has(message, MELODI_A_TTL_MS)) {
        memcpy(&ttl_ms, message->attributes[MELODI_A_TTL_MS], sizeof(ttl_ms));
        if (!ttl_ms || ttl_ms > MELODI_TTL_DEFAULT_MS)
            return -EINVAL;
    }
    return 0;
}

static int melodi_validate_radio_serial(
    const struct melodi_genl_message *message)
{
    const uint8_t *serial = message->attributes[MELODI_A_RADIO_SERIAL];
    uint16_t length = message->lengths[MELODI_A_RADIO_SERIAL];
    uint16_t index;

    if (!serial || serial[length - 1] != 0)
        return -EINVAL;
    for (index = 0; index + 1 < length; index++)
        if (serial[index] < 0x21 || serial[index] > 0x7e ||
            serial[index] == ',')
            return -EINVAL;
    return 0;
}

static int melodi_validate_bus_info(const struct melodi_genl_message *message)
{
    const uint8_t *bus = message->attributes[MELODI_A_BUS_INFO];
    uint16_t length = message->lengths[MELODI_A_BUS_INFO];
    uint16_t index;

    if (!bus || bus[length - 1] != 0)
        return -EINVAL;
    for (index = 0; index + 1 < length; index++)
        if (bus[index] < 0x21 || bus[index] > 0x7e)
            return -EINVAL;
    return 0;
}

static int melodi_validate_schema(const struct melodi_genl_message *message)
{
    const uint64_t bind = (UINT64_C(1) << MELODI_A_IFINDEX) |
                          (UINT64_C(1) << MELODI_A_LOCAL_SERVICE);
    const uint64_t peer = (UINT64_C(1) << MELODI_A_IFINDEX) |
                          (UINT64_C(1) << MELODI_A_NODE_ID);
    uint64_t allowed;
    uint64_t present = melodi_present(message);

    if (message->command == MELODI_CMD_BIND) {
        if (present != bind)
            return -EINVAL;
        return melodi_validate_bind(message);
    }
    if (message->command == MELODI_CMD_SEND) {
        allowed = (UINT64_C(1) << MELODI_A_DEST_NODE) |
                  (UINT64_C(1) << MELODI_A_DEST_SERVICE) |
                  (UINT64_C(1) << MELODI_A_PAYLOAD) |
                  (UINT64_C(1) << MELODI_A_FLAGS) |
                  (UINT64_C(1) << MELODI_A_COOKIE) |
                  (UINT64_C(1) << MELODI_A_TTL_MS) |
                  (UINT64_C(1) << MELODI_A_PRIORITY);
        if (present & ~allowed)
            return -EINVAL;
        return melodi_validate_send(message);
    }
    if (message->command == MELODI_CMD_UNBIND ||
        message->command == MELODI_CMD_GET_BINDING)
        return present == 0 ||
               (message->command == MELODI_CMD_GET_BINDING &&
                present == bind) ? 0 : -EINVAL;
    if (message->command == MELODI_CMD_RECV) {
        allowed = (UINT64_C(1) << MELODI_A_SOURCE_NODE) |
                  (UINT64_C(1) << MELODI_A_SOURCE_SERVICE) |
                  (UINT64_C(1) << MELODI_A_LOCAL_SERVICE) |
                  (UINT64_C(1) << MELODI_A_PAYLOAD) |
                  (UINT64_C(1) << MELODI_A_COOKIE) |
                  (UINT64_C(1) << MELODI_A_RX_META);
        return present == allowed ||
               present == (allowed & ~(UINT64_C(1) << MELODI_A_COOKIE)) ?
               0 : -EINVAL;
    }
    if (message->command == MELODI_CMD_ERROR) {
        allowed = (UINT64_C(1) << MELODI_A_IFINDEX) |
                  (UINT64_C(1) << MELODI_A_LOCAL_SERVICE) |
                  (UINT64_C(1) << MELODI_A_COOKIE) |
                  (UINT64_C(1) << MELODI_A_ERROR);
        return (present & (UINT64_C(1) << MELODI_A_ERROR)) &&
               !(present & ~allowed) ? 0 : -EINVAL;
    }
    if (message->command == MELODI_CMD_LINK_GET) {
        allowed = (UINT64_C(1) << MELODI_A_LINK_STATE) |
                  (UINT64_C(1) << MELODI_A_LINK_FAILURE) |
                  (UINT64_C(1) << MELODI_A_LINK_ERROR);
        if (present == (UINT64_C(1) << MELODI_A_IFINDEX))
            return 0;
        if ((present & allowed) != allowed ||
            present & ~(allowed |
                        (UINT64_C(1) << MELODI_A_RADIO_SERIAL) |
                        (UINT64_C(1) << MELODI_A_BUS_INFO) |
                        (UINT64_C(1) << MELODI_A_FRAME_PACE_US)))
            return -EINVAL;
        return melodi_has(message, MELODI_A_BUS_INFO) ?
               melodi_validate_bus_info(message) : 0;
    }
    if (message->command == MELODI_CMD_LINK_SET) {
        allowed = (UINT64_C(1) << MELODI_A_IFINDEX) |
                  (UINT64_C(1) << MELODI_A_RADIO_SERIAL);
        return present == allowed ? melodi_validate_radio_serial(message) :
                                    -EINVAL;
    }
    if (message->command == MELODI_CMD_IDENTITY_LOAD) {
        uint32_t generation;

        allowed = (UINT64_C(1) << MELODI_A_IFINDEX) |
                  (UINT64_C(1) << MELODI_A_NODE_ID) |
                  (UINT64_C(1) << MELODI_A_KEY_SERIAL) |
                  (UINT64_C(1) << MELODI_A_GENERATION);
        if (present != allowed &&
            present != (allowed |
                        (UINT64_C(1) << MELODI_A_PREVIOUS_NODE_ID)))
            return -EINVAL;
        memcpy(&generation, message->attributes[MELODI_A_GENERATION],
               sizeof(generation));
        return generation ? 0 : -EINVAL;
    }
    if (message->command == MELODI_CMD_IDENTITY_GET_PUBLIC)
        return present == (UINT64_C(1) << MELODI_A_IFINDEX) ||
               present == ((UINT64_C(1) << MELODI_A_NODE_ID) |
                           (UINT64_C(1) << MELODI_A_GENERATION)) ? 0 : -EINVAL;
    if (message->command == MELODI_CMD_PEER_DUMP) {
        uint8_t state;

        allowed = (UINT64_C(1) << MELODI_A_IFINDEX) |
                  (UINT64_C(1) << MELODI_A_NODE_ID) |
                  (UINT64_C(1) << MELODI_A_PEER_NATIVE_LOCATOR) |
                  (UINT64_C(1) << MELODI_A_COLLISION_ROUND) |
                  (UINT64_C(1) << MELODI_A_GENERATION) |
                  (UINT64_C(1) << MELODI_A_PEER_STATE) |
                  (UINT64_C(1) << MELODI_A_PEER_EXPIRY_MS) |
                  (UINT64_C(1) << MELODI_A_PEER_CAPABILITIES) |
                  (UINT64_C(1) << MELODI_A_PEER_RSSI) |
                  (UINT64_C(1) << MELODI_A_PEER_SNR) |
                  (UINT64_C(1) << MELODI_A_PEER_HOPS) |
                  (UINT64_C(1) << MELODI_A_PEER_LAST_SEEN_NS) |
                  (UINT64_C(1) << MELODI_A_PEER_POLICY);
        if (present == (UINT64_C(1) << MELODI_A_IFINDEX))
            return 0;
        if (present != allowed)
            return -EINVAL;
        memcpy(&state, message->attributes[MELODI_A_PEER_STATE],
               sizeof(state));
        if (state > MELODI_PEER_CHALLENGED)
            return -EINVAL;
        memcpy(&state, message->attributes[MELODI_A_PEER_POLICY],
               sizeof(state));
        return state <= MELODI_PEER_POLICY_BLOCKED ? 0 : -EINVAL;
    }
    if (message->command == MELODI_CMD_PEER_TRUST ||
        message->command == MELODI_CMD_PEER_BLOCK ||
        message->command == MELODI_CMD_PEER_CLEAR ||
        message->command == MELODI_CMD_PEER_REVERIFY)
        return present == peer ? 0 : -EINVAL;
    if (message->command == MELODI_CMD_POLICY_GET)
        return present == (UINT64_C(1) << MELODI_A_IFINDEX) ||
               present == (UINT64_C(1) << MELODI_A_POLICY_MODE) ? 0 : -EINVAL;
    if (message->command == MELODI_CMD_POLICY_SET) {
        uint64_t interface = UINT64_C(1) << MELODI_A_IFINDEX;
        uint64_t mode = interface |
            (UINT64_C(1) << MELODI_A_POLICY_MODE);
        uint64_t service = interface |
            (UINT64_C(1) << MELODI_A_POLICY_SERVICE) |
            (UINT64_C(1) << MELODI_A_POLICY_ACTION);
        uint64_t broadcast = interface |
            (UINT64_C(1) << MELODI_A_POLICY_BROADCAST);
        uint64_t reset = interface |
            (UINT64_C(1) << MELODI_A_POLICY_RESET);
        uint8_t value;

        if (present == service) {
            memcpy(&value, message->attributes[MELODI_A_POLICY_ACTION],
                   sizeof(value));
            return value >= MELODI_POLICY_SERVICE_ALLOW &&
                   value <= MELODI_POLICY_SERVICE_CLEAR ? 0 : -EINVAL;
        }
        if (present == broadcast) {
            memcpy(&value, message->attributes[MELODI_A_POLICY_BROADCAST],
                   sizeof(value));
            return value <= 1 ? 0 : -EINVAL;
        }
        if (present == reset) {
            memcpy(&value, message->attributes[MELODI_A_POLICY_RESET],
                   sizeof(value));
            return value == 1 ? 0 : -EINVAL;
        }
        return present == mode ? 0 : -EINVAL;
    }
    if (message->command == MELODI_CMD_DISCOVER)
        return present == (UINT64_C(1) << MELODI_A_IFINDEX) ? 0 : -EINVAL;
    if (message->command == MELODI_CMD_STATS_GET)
        return present == (UINT64_C(1) << MELODI_A_IFINDEX) ||
               present == (UINT64_C(1) << MELODI_A_STATS) ? 0 : -EINVAL;
    if (message->command == MELODI_CMD_MONITOR_BIND)
        return present == (UINT64_C(1) << MELODI_A_IFINDEX) ? 0 : -EINVAL;
    if (message->command == MELODI_CMD_MONITOR_FRAME) {
        uint8_t direction;

        allowed = (UINT64_C(1) << MELODI_A_IFINDEX) |
                  (UINT64_C(1) << MELODI_A_MONITOR_DIRECTION) |
                  (UINT64_C(1) << MELODI_A_FRAME);
        if (present != allowed &&
            present != (allowed | (UINT64_C(1) << MELODI_A_RX_META)))
            return -EINVAL;
        memcpy(&direction,
               message->attributes[MELODI_A_MONITOR_DIRECTION],
               sizeof(direction));
        return (direction == MELODI_MONITOR_RX) ==
                   melodi_has(message, MELODI_A_RX_META) &&
               direction <= MELODI_MONITOR_TX ? 0 : -EINVAL;
    }
    return -EOPNOTSUPP;
}

static int melodi_nested_width(uint16_t outer, uint16_t type,
                               const uint8_t *value, uint16_t length)
{
    if (outer == MELODI_A_RX_META) {
        if (type == MELODI_RX_A_AUTHENTICATED)
            return length == sizeof(uint8_t) && value[0] <= 1;
        if (type == MELODI_RX_A_DUPLICATES)
            return length == sizeof(uint16_t);
        if (type == MELODI_RX_A_HOPS ||
            type == MELODI_RX_A_RETRANSMISSIONS)
            return length == sizeof(uint8_t);
        if (type == MELODI_RX_A_RSSI || type == MELODI_RX_A_SNR)
            return length == sizeof(int16_t);
        if (type == MELODI_RX_A_TIMESTAMP_NS)
            return length == sizeof(uint64_t);
        return 0;
    }
    if (outer == MELODI_A_STATS)
        return type <= MELODI_STAT_A_MAX && length == sizeof(uint64_t);
    if (type == MELODI_ERROR_A_CODE)
        return length == sizeof(int32_t);
    if (type == MELODI_ERROR_A_DETAIL)
        return length > 0 && length <= 128 && value[length - 1] == 0;
    return 0;
}

static int melodi_validate_nested(uint16_t outer, const uint8_t *position,
                                  size_t remaining)
{
    uint64_t seen = 0;
    const struct nlattr *attribute;
    size_t aligned_length;
    size_t raw_length;
    uint16_t maximum = outer == MELODI_A_RX_META ? MELODI_RX_A_MAX :
                       (outer == MELODI_A_STATS ? MELODI_STAT_A_MAX :
                                                  MELODI_ERROR_A_MAX);
    uint16_t type;
    size_t index;

    while (remaining) {
        if (remaining < sizeof(*attribute))
            return -EPROTO;
        attribute = (const struct nlattr *)position;
        raw_length = attribute->nla_len;
        if (raw_length < sizeof(*attribute) || raw_length > remaining)
            return -EPROTO;
        aligned_length = MELODI_ALIGN(raw_length);
        if (aligned_length > remaining)
            return -EPROTO;
        type = attribute->nla_type;
        if (type == 0 && raw_length == sizeof(*attribute)) {
            position += aligned_length;
            remaining -= aligned_length;
            continue;
        }
        if (type > maximum || type == 0 || type >= 64 ||
            seen & (UINT64_C(1) << type) ||
            !melodi_nested_width(outer, type,
                position + sizeof(*attribute),
                raw_length - sizeof(*attribute)))
            return -EINVAL;
        for (index = raw_length; index < aligned_length; index++)
            if (position[index] != 0)
                return -EPROTO;
        seen |= UINT64_C(1) << type;
        position += aligned_length;
        remaining -= aligned_length;
    }
    if (outer == MELODI_A_RX_META)
        return seen == ((UINT64_C(1) << (MELODI_RX_A_MAX + 1)) - 2) ?
               0 : -EINVAL;
    if (outer == MELODI_A_STATS)
        return seen == ((UINT64_C(1) << (MELODI_STAT_A_MAX + 1)) - 2) ?
               0 : -EINVAL;
    return seen & (UINT64_C(1) << MELODI_ERROR_A_CODE) ? 0 : -EINVAL;
}

int melodi_genl_begin(struct melodi_genl_builder *builder, void *buffer,
                      size_t capacity, uint16_t family, uint16_t flags,
                      uint32_t sequence, uint32_t portid, uint8_t command)
{
    struct nlmsghdr *netlink;
    struct genlmsghdr *generic;
    size_t header_length = NLMSG_HDRLEN + GENL_HDRLEN;

    if (!builder || !buffer || capacity < header_length ||
        !melodi_command_valid(command))
        return -EINVAL;
    memset(buffer, 0, capacity);
    builder->data = buffer;
    builder->capacity = capacity;
    builder->length = header_length;
    netlink = buffer;
    netlink->nlmsg_len = header_length;
    netlink->nlmsg_type = family;
    netlink->nlmsg_flags = flags;
    netlink->nlmsg_seq = sequence;
    netlink->nlmsg_pid = portid;
    generic = (struct genlmsghdr *)(builder->data + NLMSG_HDRLEN);
    generic->cmd = command;
    generic->version = MELODI_GENL_VERSION;
    generic->reserved = 0;
    return 0;
}

int melodi_genl_put(struct melodi_genl_builder *builder, uint16_t type,
                    const void *value, uint16_t length)
{
    struct nlattr *attribute;
    size_t raw_length = sizeof(*attribute) + length;
    size_t aligned_length = MELODI_ALIGN(raw_length);

    if (!builder || (!value && length) || type == MELODI_A_UNSPEC ||
        type > MELODI_A_MAX || !melodi_attribute_width(type, length) ||
        aligned_length > builder->capacity - builder->length)
        return -EINVAL;
    attribute = (struct nlattr *)(builder->data + builder->length);
    attribute->nla_len = raw_length;
    attribute->nla_type = type;
    if (length)
        memcpy((uint8_t *)attribute + sizeof(*attribute), value, length);
    memset((uint8_t *)attribute + raw_length, 0, aligned_length - raw_length);
    builder->length += aligned_length;
    return 0;
}

int melodi_genl_put_u8(struct melodi_genl_builder *builder, uint16_t type,
                       uint8_t value)
{
    return melodi_genl_put(builder, type, &value, sizeof(value));
}

int melodi_genl_put_u16(struct melodi_genl_builder *builder, uint16_t type,
                        uint16_t value)
{
    return melodi_genl_put(builder, type, &value, sizeof(value));
}

int melodi_genl_put_u32(struct melodi_genl_builder *builder, uint16_t type,
                        uint32_t value)
{
    return melodi_genl_put(builder, type, &value, sizeof(value));
}

int melodi_genl_put_u64(struct melodi_genl_builder *builder, uint16_t type,
                        uint64_t value)
{
    return melodi_genl_put(builder, type, &value, sizeof(value));
}

int melodi_genl_end(struct melodi_genl_builder *builder)
{
    struct nlmsghdr *header;

    if (!builder || !builder->data || builder->length > UINT32_MAX)
        return -EINVAL;
    header = (struct nlmsghdr *)builder->data;
    header->nlmsg_len = builder->length;
    return 0;
}

int melodi_genl_parse(const void *buffer, size_t length,
                      struct melodi_genl_message *message)
{
    const struct nlmsghdr *netlink = buffer;
    const struct genlmsghdr *generic;
    const struct nlattr *attribute;
    const uint8_t *position;
    size_t remaining;
    size_t raw_length;
    size_t aligned_length;
    uint16_t type;
    uint16_t flags;
    size_t index;

    if (!buffer || !message || length < NLMSG_HDRLEN + GENL_HDRLEN)
        return -EINVAL;
    if (netlink->nlmsg_len != length)
        return -EPROTO;
    generic = (const struct genlmsghdr *)((const uint8_t *)buffer + NLMSG_HDRLEN);
    if (generic->version != MELODI_GENL_VERSION || generic->reserved != 0 ||
        !melodi_command_valid(generic->cmd))
        return -EPROTO;
    memset(message, 0, sizeof(*message));
    message->family = netlink->nlmsg_type;
    message->flags = netlink->nlmsg_flags;
    message->sequence = netlink->nlmsg_seq;
    message->portid = netlink->nlmsg_pid;
    message->command = generic->cmd;
    position = (const uint8_t *)generic + GENL_HDRLEN;
    remaining = length - NLMSG_HDRLEN - GENL_HDRLEN;
    while (remaining != 0) {
        if (remaining < sizeof(*attribute))
            return -EPROTO;
        attribute = (const struct nlattr *)position;
        raw_length = attribute->nla_len;
        if (raw_length < sizeof(*attribute) || raw_length > remaining)
            return -EPROTO;
        aligned_length = MELODI_ALIGN(raw_length);
        if (aligned_length > remaining)
            return -EPROTO;
        type = attribute->nla_type & NLA_TYPE_MASK;
        flags = attribute->nla_type & ~NLA_TYPE_MASK;
        if (type == MELODI_A_UNSPEC || type > MELODI_A_MAX ||
            message->attributes[type] ||
            !melodi_attribute_width(type, raw_length - sizeof(*attribute)))
            return -EINVAL;
        if ((type == MELODI_A_RX_META || type == MELODI_A_ERROR ||
             type == MELODI_A_STATS) ?
            flags != NLA_F_NESTED : flags != 0)
            return -EINVAL;
        if ((type == MELODI_A_RX_META || type == MELODI_A_ERROR ||
             type == MELODI_A_STATS) &&
            melodi_validate_nested(type, position + sizeof(*attribute),
                                   raw_length - sizeof(*attribute)))
            return -EINVAL;
        for (index = raw_length; index < aligned_length; index++)
            if (position[index] != 0)
                return -EPROTO;
        message->attributes[type] = position + sizeof(*attribute);
        message->lengths[type] = raw_length - sizeof(*attribute);
        position += aligned_length;
        remaining -= aligned_length;
    }
    return melodi_validate_schema(message);
}
