/* SPDX-License-Identifier: GPL-2.0-only */
#include "genl.h"

#include <assert.h>
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <string.h>

static size_t build_bind(uint8_t *buffer, size_t capacity)
{
    struct melodi_genl_builder builder;

    assert(melodi_genl_begin(&builder, buffer, capacity, 0x1234,
                             NLM_F_REQUEST | NLM_F_ACK, 0x10203040,
                             0x55667788, MELODI_CMD_BIND) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_IFINDEX, 7) == 0);
    assert(melodi_genl_put_u16(&builder, MELODI_A_LOCAL_SERVICE, 42) == 0);
    assert(melodi_genl_end(&builder) == 0);
    return builder.length;
}

static void test_bind(void)
{
    uint8_t buffer[128];
    struct melodi_genl_message message;
    size_t length = build_bind(buffer, sizeof(buffer));

    assert(melodi_genl_parse(buffer, length, &message) == 0);
    assert(message.command == MELODI_CMD_BIND);
    assert(message.lengths[MELODI_A_IFINDEX] == sizeof(uint32_t));
    assert(message.lengths[MELODI_A_LOCAL_SERVICE] == sizeof(uint16_t));
    assert(melodi_genl_parse(buffer, length - 1, &message) == -EPROTO);
    buffer[length - 1] = 1;
    assert(melodi_genl_parse(buffer, length, &message) == -EPROTO);
}

static void test_duplicate(void)
{
    uint8_t buffer[128];
    struct melodi_genl_builder builder;
    struct melodi_genl_message message;

    assert(melodi_genl_begin(&builder, buffer, sizeof(buffer), 1, 0, 0, 0,
                             MELODI_CMD_BIND) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_IFINDEX, 7) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_IFINDEX, 8) == 0);
    assert(melodi_genl_put_u16(&builder, MELODI_A_LOCAL_SERVICE, 9) == 0);
    assert(melodi_genl_end(&builder) == 0);
    assert(melodi_genl_parse(buffer, builder.length, &message) == -EINVAL);
}

static void test_send_rules(void)
{
    uint8_t buffer[256];
    uint8_t payload[] = { 1, 2, 3 };
    struct melodi_node_id node = { .bytes = { 1 } };
    struct melodi_genl_builder builder;
    struct melodi_genl_message message;

    assert(melodi_genl_begin(&builder, buffer, sizeof(buffer), 1, 0, 0, 0,
                             MELODI_CMD_SEND) == 0);
    assert(melodi_genl_put_u16(&builder, MELODI_A_DEST_SERVICE, 9) == 0);
    assert(melodi_genl_put(&builder, MELODI_A_PAYLOAD, payload,
                           sizeof(payload)) == 0);
    assert(melodi_genl_end(&builder) == 0);
    assert(melodi_genl_parse(buffer, builder.length, &message) == -EINVAL);
    assert(melodi_genl_put(&builder, MELODI_A_DEST_NODE, node.bytes,
                           sizeof(node.bytes)) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_TTL_MS, 5000) == 0);
    assert(melodi_genl_end(&builder) == 0);
    assert(melodi_genl_parse(buffer, builder.length, &message) == 0);
    *(uint32_t *)message.attributes[MELODI_A_TTL_MS] = 0;
    assert(melodi_genl_parse(buffer, builder.length, &message) == -EINVAL);
    *(uint32_t *)message.attributes[MELODI_A_TTL_MS] =
        MELODI_TTL_DEFAULT_MS + 1;
    assert(melodi_genl_parse(buffer, builder.length, &message) == -EINVAL);
}

static void test_broadcast_rules(void)
{
    uint8_t buffer[768];
    uint8_t payload[MELODI_BROADCAST_MTU + 1] = { 0 };
    struct melodi_genl_builder builder;
    struct melodi_genl_message message;
    uint32_t *flags;

    assert(melodi_genl_begin(&builder, buffer, sizeof(buffer), 1, 0, 0, 0,
                             MELODI_CMD_SEND) == 0);
    assert(melodi_genl_put_u16(&builder, MELODI_A_DEST_SERVICE, 9) == 0);
    assert(melodi_genl_put(&builder, MELODI_A_PAYLOAD, payload,
                           MELODI_BROADCAST_MTU) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_FLAGS,
                               MELODI_F_BROADCAST) == 0);
    assert(melodi_genl_end(&builder) == 0);
    assert(melodi_genl_parse(buffer, builder.length, &message) == 0);
    flags = (uint32_t *)message.attributes[MELODI_A_FLAGS];
    *flags |= MELODI_F_RELIABLE;
    assert(melodi_genl_parse(buffer, builder.length, &message) == -EINVAL);

    assert(melodi_genl_begin(&builder, buffer, sizeof(buffer), 1, 0, 0, 0,
                             MELODI_CMD_SEND) == 0);
    assert(melodi_genl_put_u16(&builder, MELODI_A_DEST_SERVICE, 9) == 0);
    assert(melodi_genl_put(&builder, MELODI_A_PAYLOAD, payload,
                           sizeof(payload)) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_FLAGS,
                               MELODI_F_BROADCAST) == 0);
    assert(melodi_genl_end(&builder) == 0);
    assert(melodi_genl_parse(buffer, builder.length, &message) == -EMSGSIZE);
}

static void test_nested_attribute_flags(void)
{
    uint8_t buffer[256];
    struct {
        struct nlattr attribute;
        int32_t code;
    } nested_payload = {
        .attribute = {
            .nla_len = sizeof(nested_payload),
            .nla_type = MELODI_ERROR_A_CODE,
        },
        .code = -5,
    };
    struct melodi_genl_builder builder;
    struct melodi_genl_message message;
    struct nlattr *attribute;

    assert(melodi_genl_begin(&builder, buffer, sizeof(buffer), 1, 0, 0, 0,
                             MELODI_CMD_ERROR) == 0);
    assert(melodi_genl_put(&builder, MELODI_A_ERROR, &nested_payload,
                           sizeof(nested_payload)) == 0);
    assert(melodi_genl_end(&builder) == 0);
    attribute = (struct nlattr *)(buffer + NLMSG_HDRLEN + GENL_HDRLEN);
    assert(melodi_genl_parse(buffer, builder.length, &message) == -EINVAL);
    attribute->nla_type |= NLA_F_NESTED;
    assert(melodi_genl_parse(buffer, builder.length, &message) == 0);
    attribute->nla_type |= NLA_F_NET_BYTEORDER;
    assert(melodi_genl_parse(buffer, builder.length, &message) == -EINVAL);
}

static void test_link_status(void)
{
    static const char bus[] = "melodi-loop";
    uint8_t buffer[128];
    struct melodi_genl_builder builder;
    struct melodi_genl_message message;
    int32_t error = -EPROTONOSUPPORT;

    assert(melodi_genl_begin(&builder, buffer, sizeof(buffer), 1, 0, 0, 0,
                             MELODI_CMD_LINK_GET) == 0);
    assert(melodi_genl_put_u8(&builder, MELODI_A_LINK_STATE,
                              MELODI_LINK_FAILED) == 0);
    assert(melodi_genl_put_u16(&builder, MELODI_A_LINK_FAILURE,
                               MELODI_LINK_FAILURE_FIRMWARE) == 0);
    assert(melodi_genl_put(&builder, MELODI_A_LINK_ERROR, &error,
                           sizeof(error)) == 0);
    assert(melodi_genl_put(&builder, MELODI_A_BUS_INFO, bus,
                           sizeof(bus)) == 0);
    assert(melodi_genl_end(&builder) == 0);
    assert(melodi_genl_parse(buffer, builder.length, &message) == 0);
    ((struct nlattr *)((uint8_t *)message.attributes[MELODI_A_BUS_INFO] -
                       sizeof(struct nlattr)))->nla_type =
        MELODI_A_LINK_FAILURE;
    assert(melodi_genl_parse(buffer, builder.length, &message) == -EINVAL);
}

static void test_link_selector(void)
{
    static const char serial[] = "DF643CF0134A4C26";
    uint8_t buffer[128];
    struct melodi_genl_builder builder;
    struct melodi_genl_message message;

    assert(melodi_genl_begin(&builder, buffer, sizeof(buffer), 1, 0, 0, 0,
                             MELODI_CMD_LINK_SET) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_IFINDEX, 7) == 0);
    assert(melodi_genl_put(&builder, MELODI_A_RADIO_SERIAL, serial,
                           sizeof(serial)) == 0);
    assert(melodi_genl_end(&builder) == 0);
    assert(melodi_genl_parse(buffer, builder.length, &message) == 0);
    ((char *)message.attributes[MELODI_A_RADIO_SERIAL])
        [sizeof(serial) - 1] = 'x';
    assert(melodi_genl_parse(buffer, builder.length, &message) == -EINVAL);
}

static void test_identity_generation(void)
{
    struct melodi_node_id node = { .bytes = { 1, 2 } };
    struct melodi_node_id previous = { .bytes = { 1, 3 } };
    uint8_t buffer[256];
    struct melodi_genl_builder builder;
    struct melodi_genl_message message;

    assert(melodi_genl_begin(&builder, buffer, sizeof(buffer), 1, 0, 0, 0,
                             MELODI_CMD_IDENTITY_LOAD) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_IFINDEX, 7) == 0);
    assert(melodi_genl_put(&builder, MELODI_A_NODE_ID, node.bytes,
                           sizeof(node.bytes)) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_KEY_SERIAL, 8) == 0);
    assert(melodi_genl_end(&builder) == 0);
    assert(melodi_genl_parse(buffer, builder.length, &message) == -EINVAL);
    assert(melodi_genl_put_u32(&builder, MELODI_A_GENERATION, 9) == 0);
    assert(melodi_genl_end(&builder) == 0);
    assert(melodi_genl_parse(buffer, builder.length, &message) == 0);
    *(uint32_t *)message.attributes[MELODI_A_GENERATION] = 0;
    assert(melodi_genl_parse(buffer, builder.length, &message) == -EINVAL);
    *(uint32_t *)message.attributes[MELODI_A_GENERATION] = 9;
    assert(melodi_genl_put(&builder, MELODI_A_PREVIOUS_NODE_ID,
                           previous.bytes, sizeof(previous.bytes)) == 0);
    assert(melodi_genl_end(&builder) == 0);
    assert(melodi_genl_parse(buffer, builder.length, &message) == 0);

    assert(melodi_genl_begin(&builder, buffer, sizeof(buffer), 1, 0, 0, 0,
                             MELODI_CMD_IDENTITY_GET_PUBLIC) == 0);
    assert(melodi_genl_put(&builder, MELODI_A_NODE_ID, node.bytes,
                           sizeof(node.bytes)) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_GENERATION, 9) == 0);
    assert(melodi_genl_end(&builder) == 0);
    assert(melodi_genl_parse(buffer, builder.length, &message) == 0);
}

static void test_peer_dump(void)
{
    struct melodi_node_id node = { .bytes = { 1, 2 } };
    int16_t rssi = -93;
    int16_t snr = 7;
    uint8_t buffer[384];
    struct melodi_genl_builder builder;
    struct melodi_genl_message message;

    assert(melodi_genl_begin(&builder, buffer, sizeof(buffer), 1, 0, 0, 0,
                             MELODI_CMD_PEER_DUMP) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_IFINDEX, 7) == 0);
    assert(melodi_genl_put(&builder, MELODI_A_NODE_ID, node.bytes,
                           sizeof(node.bytes)) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_PEER_NATIVE_LOCATOR,
                               0x10203040) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_COLLISION_ROUND, 2) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_GENERATION, 3) == 0);
    assert(melodi_genl_put_u8(&builder, MELODI_A_PEER_STATE,
                              MELODI_PEER_AUTHENTICATED) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_PEER_EXPIRY_MS,
                               25000) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_PEER_CAPABILITIES,
                               0x5) == 0);
    assert(melodi_genl_put(&builder, MELODI_A_PEER_RSSI,
                           &rssi, sizeof(rssi)) == 0);
    assert(melodi_genl_put(&builder, MELODI_A_PEER_SNR,
                           &snr, sizeof(snr)) == 0);
    assert(melodi_genl_put_u8(&builder, MELODI_A_PEER_HOPS, 2) == 0);
    assert(melodi_genl_put_u64(&builder, MELODI_A_PEER_LAST_SEEN_NS,
                               123456789) == 0);
    assert(melodi_genl_put_u8(&builder, MELODI_A_PEER_POLICY,
                              MELODI_PEER_POLICY_DEFAULT) == 0);
    assert(melodi_genl_end(&builder) == 0);
    assert(melodi_genl_parse(buffer, builder.length, &message) == 0);
    *(uint8_t *)message.attributes[MELODI_A_PEER_STATE] =
        MELODI_PEER_CHALLENGED + 1;
    assert(melodi_genl_parse(buffer, builder.length, &message) == -EINVAL);
    *(uint8_t *)message.attributes[MELODI_A_PEER_STATE] =
        MELODI_PEER_AUTHENTICATED;
    ((struct nlattr *)((uint8_t *)message.attributes[MELODI_A_PEER_HOPS] -
                       sizeof(struct nlattr)))->nla_type =
        MELODI_A_PEER_LAST_SEEN_NS;
    assert(melodi_genl_parse(buffer, builder.length, &message) == -EINVAL);
}

static void test_policy_rules(void)
{
    uint8_t buffer[128];
    struct melodi_genl_builder builder;
    struct melodi_genl_message message;

    assert(melodi_genl_begin(&builder, buffer, sizeof(buffer), 1, 0, 0, 0,
                             MELODI_CMD_POLICY_SET) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_IFINDEX, 7) == 0);
    assert(melodi_genl_put_u16(&builder, MELODI_A_POLICY_SERVICE,
                               12345) == 0);
    assert(melodi_genl_put_u8(&builder, MELODI_A_POLICY_ACTION,
                              MELODI_POLICY_SERVICE_DENY) == 0);
    assert(melodi_genl_end(&builder) == 0);
    assert(melodi_genl_parse(buffer, builder.length, &message) == 0);
    *(uint8_t *)message.attributes[MELODI_A_POLICY_ACTION] = 0;
    assert(melodi_genl_parse(buffer, builder.length, &message) == -EINVAL);

    assert(melodi_genl_begin(&builder, buffer, sizeof(buffer), 1, 0, 0, 0,
                             MELODI_CMD_POLICY_SET) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_IFINDEX, 7) == 0);
    assert(melodi_genl_put_u8(&builder, MELODI_A_POLICY_BROADCAST, 0) == 0);
    assert(melodi_genl_end(&builder) == 0);
    assert(melodi_genl_parse(buffer, builder.length, &message) == 0);
    *(uint8_t *)message.attributes[MELODI_A_POLICY_BROADCAST] = 2;
    assert(melodi_genl_parse(buffer, builder.length, &message) == -EINVAL);

    assert(melodi_genl_begin(&builder, buffer, sizeof(buffer), 1, 0, 0, 0,
                             MELODI_CMD_POLICY_SET) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_IFINDEX, 7) == 0);
    assert(melodi_genl_put_u8(&builder, MELODI_A_POLICY_RESET, 1) == 0);
    assert(melodi_genl_end(&builder) == 0);
    assert(melodi_genl_parse(buffer, builder.length, &message) == 0);
    *(uint8_t *)message.attributes[MELODI_A_POLICY_RESET] = 0;
    assert(melodi_genl_parse(buffer, builder.length, &message) == -EINVAL);
}

static void test_stats_and_monitor(void)
{
    uint8_t buffer[1024];
    uint8_t frame[MELODI_FRAME_HEADER_MIN] = { 0 };
    union {
        uint64_t alignment;
        uint8_t data[MELODI_STAT_A_MAX * (sizeof(struct nlattr) +
                                           sizeof(uint64_t))];
    } nested = { 0 };
    struct melodi_genl_builder builder;
    struct melodi_genl_message message;
    struct nlattr *attribute;
    uint64_t value;
    size_t offset = 0;
    unsigned int index;

    for (index = 1; index <= MELODI_STAT_A_MAX; index++) {
        attribute = (struct nlattr *)(nested.data + offset);
        attribute->nla_len = sizeof(*attribute) + sizeof(value);
        attribute->nla_type = index;
        value = index;
        memcpy(nested.data + offset + sizeof(*attribute), &value,
               sizeof(value));
        offset += attribute->nla_len;
    }
    assert(melodi_genl_begin(&builder, buffer, sizeof(buffer), 1, 0, 0, 0,
                             MELODI_CMD_STATS_GET) == 0);
    assert(melodi_genl_put(&builder, MELODI_A_STATS, nested.data, offset) == 0);
    assert(melodi_genl_end(&builder) == 0);
    attribute = (struct nlattr *)(buffer + NLMSG_HDRLEN + GENL_HDRLEN);
    attribute->nla_type |= NLA_F_NESTED;
    assert(melodi_genl_parse(buffer, builder.length, &message) == 0);

    assert(melodi_genl_begin(&builder, buffer, sizeof(buffer), 1, 0, 0, 0,
                             MELODI_CMD_MONITOR_FRAME) == 0);
    assert(melodi_genl_put_u32(&builder, MELODI_A_IFINDEX, 7) == 0);
    assert(melodi_genl_put_u8(&builder, MELODI_A_MONITOR_DIRECTION,
                              MELODI_MONITOR_TX) == 0);
    assert(melodi_genl_put(&builder, MELODI_A_FRAME, frame,
                           sizeof(frame)) == 0);
    assert(melodi_genl_end(&builder) == 0);
    assert(melodi_genl_parse(buffer, builder.length, &message) == 0);
    *(uint8_t *)message.attributes[MELODI_A_MONITOR_DIRECTION] =
        MELODI_MONITOR_RX;
    assert(melodi_genl_parse(buffer, builder.length, &message) == -EINVAL);
}

int main(void)
{
    test_bind();
    test_duplicate();
    test_send_rules();
    test_broadcast_rules();
    test_nested_attribute_flags();
    test_link_status();
    test_link_selector();
    test_identity_generation();
    test_peer_dump();
    test_policy_rules();
    test_stats_and_monitor();
    return 0;
}
