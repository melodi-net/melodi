/* SPDX-License-Identifier: GPL-2.0-only */
#include "client.h"

#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

static int melodi_client_attributes(struct melodi_genl_builder *builder,
                                    uint8_t *buffer, size_t capacity)
{
    return melodi_genl_begin(builder, buffer, capacity, 1, 0, 0, 0,
                             MELODI_CMD_BIND);
}

static int melodi_client_command(struct melodi_socket *socket_state,
                                 uint8_t command,
                                 struct melodi_genl_builder *attributes)
{
    uint8_t reply_buffer[4096];
    struct melodi_genl_message reply;
    size_t offset = NLMSG_HDRLEN + GENL_HDRLEN;

    return melodi_socket_command(socket_state, command,
                                 attributes->data + offset,
                                 attributes->length - offset, false, &reply,
                                 reply_buffer, sizeof(reply_buffer));
}

static int melodi_client_error(const struct melodi_genl_message *message)
{
    const uint8_t *position = message->attributes[MELODI_A_ERROR];
    size_t remaining = message->lengths[MELODI_A_ERROR];

    while (remaining >= sizeof(struct nlattr)) {
        const struct nlattr *attribute = (const struct nlattr *)position;
        size_t aligned = NLA_ALIGN(attribute->nla_len);

        if (attribute->nla_type == MELODI_ERROR_A_CODE) {
            int32_t code;

            memcpy(&code, position + sizeof(*attribute), sizeof(code));
            return code < 0 ? code : -EPROTO;
        }
        position += aligned;
        remaining -= aligned;
    }
    return -EPROTO;
}

int melodi_client_bind(struct melodi_socket *socket_state, uint32_t ifindex,
                       uint16_t service)
{
    uint8_t attributes_buffer[64];
    struct melodi_genl_builder attributes;
    int error;

    error = melodi_client_attributes(&attributes, attributes_buffer,
                                     sizeof(attributes_buffer));
    if (!error)
        error = melodi_genl_put_u32(&attributes, MELODI_A_IFINDEX, ifindex);
    if (!error)
        error = melodi_genl_put_u16(&attributes, MELODI_A_LOCAL_SERVICE,
                                    service);
    if (error)
        return error;
    return melodi_client_command(socket_state, MELODI_CMD_BIND, &attributes);
}

int melodi_client_send(struct melodi_socket *socket_state,
                       const struct melodi_node_id *destination,
                       uint16_t destination_service, const void *payload,
                       size_t payload_length, uint32_t flags, uint64_t cookie)
{
    uint8_t attributes_buffer[MELODI_MESSAGE_MTU + 128];
    struct melodi_genl_builder attributes;
    bool broadcast = flags & MELODI_F_BROADCAST;
    int error;

    if ((!payload && payload_length) || payload_length > MELODI_MESSAGE_MTU ||
        flags & ~MELODI_F_ALL || broadcast == !!destination ||
        (broadcast && payload_length > MELODI_BROADCAST_MTU) ||
        (broadcast &&
         (flags & (MELODI_F_RELIABLE | MELODI_F_ORDERED))) ||
        (!broadcast &&
         melodi_nodeid_validate(destination) != MELODI_NODEID_OK))
        return -EINVAL;
    error = melodi_client_attributes(&attributes, attributes_buffer,
                                     sizeof(attributes_buffer));
    if (!error && !broadcast)
        error = melodi_genl_put(&attributes, MELODI_A_DEST_NODE,
                                destination->bytes, sizeof(destination->bytes));
    if (!error)
        error = melodi_genl_put_u16(&attributes, MELODI_A_DEST_SERVICE,
                                    destination_service);
    if (!error)
        error = melodi_genl_put(&attributes, MELODI_A_PAYLOAD, payload,
                                payload_length);
    if (!error && flags)
        error = melodi_genl_put_u32(&attributes, MELODI_A_FLAGS, flags);
    if (!error && cookie)
        error = melodi_genl_put_u64(&attributes, MELODI_A_COOKIE, cookie);
    if (error)
        return error;
    return melodi_client_command(socket_state, MELODI_CMD_SEND, &attributes);
}

int melodi_client_receive(struct melodi_socket *socket_state, void *buffer,
                          size_t capacity,
                          struct melodi_received_message *message)
{
    struct melodi_genl_message parsed;
    struct nlmsghdr *header;
    ssize_t received;
    int error;

    if (!socket_state || !buffer || !message || capacity < NLMSG_HDRLEN)
        return -EINVAL;
    for (;;) {
        received = recv(socket_state->descriptor, buffer, capacity, 0);
        if (received < 0)
            return -errno;
        if ((size_t)received < NLMSG_HDRLEN)
            return -EPROTO;
        header = buffer;
        if (header->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *netlink_error = NLMSG_DATA(header);

            return netlink_error->error ? netlink_error->error : 0;
        }
        if (header->nlmsg_type != socket_state->family)
            continue;
        error = melodi_genl_parse(buffer, header->nlmsg_len, &parsed);
        if (error)
            return error;
        if (parsed.command == MELODI_CMD_ERROR)
            return melodi_client_error(&parsed);
        if (parsed.command != MELODI_CMD_RECV)
            continue;
        if (!parsed.attributes[MELODI_A_SOURCE_NODE] ||
            !parsed.attributes[MELODI_A_SOURCE_SERVICE] ||
            !parsed.attributes[MELODI_A_LOCAL_SERVICE] ||
            !parsed.attributes[MELODI_A_PAYLOAD])
            return -EPROTO;
        memcpy(&message->source, parsed.attributes[MELODI_A_SOURCE_NODE],
               sizeof(message->source));
        memcpy(&message->source_service,
               parsed.attributes[MELODI_A_SOURCE_SERVICE],
               sizeof(message->source_service));
        memcpy(&message->local_service,
               parsed.attributes[MELODI_A_LOCAL_SERVICE],
               sizeof(message->local_service));
        message->payload = parsed.attributes[MELODI_A_PAYLOAD];
        message->payload_length = parsed.lengths[MELODI_A_PAYLOAD];
        return melodi_nodeid_validate(&message->source) == MELODI_NODEID_OK ?
               0 : -EPROTO;
    }
}
