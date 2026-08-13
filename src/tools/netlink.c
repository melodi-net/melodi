/* SPDX-License-Identifier: GPL-2.0-only */
#include "netlink.h"

#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MELODI_NL_ALIGN(value) (((value) + 3U) & ~3U)

struct melodi_control_request {
    struct nlmsghdr netlink;
    struct genlmsghdr generic;
    struct nlattr attribute;
    char family_name[8];
};

static int melodi_send_buffer(struct melodi_socket *socket_state,
                              const void *buffer, size_t length)
{
    struct sockaddr_nl address = { .nl_family = AF_NETLINK };
    struct iovec vector = { .iov_base = (void *)buffer, .iov_len = length };
    struct msghdr message = {
        .msg_name = &address,
        .msg_namelen = sizeof(address),
        .msg_iov = &vector,
        .msg_iovlen = 1,
    };
    ssize_t sent;

    sent = sendmsg(socket_state->descriptor, &message, 0);
    if (sent < 0)
        return -errno;
    return (size_t)sent == length ? 0 : -EIO;
}

static ssize_t melodi_receive_buffer(struct melodi_socket *socket_state,
                                     void *buffer, size_t capacity)
{
    ssize_t received = recv(socket_state->descriptor, buffer, capacity, 0);

    return received < 0 ? -errno : received;
}

static int melodi_resolve_family(struct melodi_socket *socket_state)
{
    struct melodi_control_request request = { 0 };
    uint8_t response[4096];
    struct nlmsghdr *header;
    struct genlmsghdr *generic;
    struct nlattr *attribute;
    size_t remaining;
    ssize_t received;
    int error;

    request.netlink.nlmsg_len = sizeof(request);
    request.netlink.nlmsg_type = GENL_ID_CTRL;
    request.netlink.nlmsg_flags = NLM_F_REQUEST;
    request.netlink.nlmsg_seq = ++socket_state->sequence;
    request.netlink.nlmsg_pid = socket_state->portid;
    request.generic.cmd = CTRL_CMD_GETFAMILY;
    request.generic.version = 1;
    request.attribute.nla_len = sizeof(request.attribute) +
                                sizeof(MELODI_GENL_NAME);
    request.attribute.nla_type = CTRL_ATTR_FAMILY_NAME;
    memcpy(request.family_name, MELODI_GENL_NAME, sizeof(MELODI_GENL_NAME));
    error = melodi_send_buffer(socket_state, &request, sizeof(request));
    if (error)
        return error;
    received = melodi_receive_buffer(socket_state, response, sizeof(response));
    if (received < 0)
        return received;
    if ((size_t)received < NLMSG_HDRLEN)
        return -EPROTO;
    header = (struct nlmsghdr *)response;
    if (header->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *error = NLMSG_DATA(header);

        return error->error ? error->error : -ENOENT;
    }
    if (header->nlmsg_len > (size_t)received ||
        header->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN)
        return -EPROTO;
    generic = NLMSG_DATA(header);
    remaining = header->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
    attribute = (struct nlattr *)((uint8_t *)generic + GENL_HDRLEN);
    while (remaining >= sizeof(*attribute)) {
        size_t aligned;

        if (attribute->nla_len < sizeof(*attribute) ||
            attribute->nla_len > remaining)
            return -EPROTO;
        if (attribute->nla_type == CTRL_ATTR_FAMILY_ID &&
            attribute->nla_len == sizeof(*attribute) + sizeof(uint16_t)) {
            memcpy(&socket_state->family, (uint8_t *)attribute +
                   sizeof(*attribute), sizeof(socket_state->family));
            return 0;
        }
        aligned = MELODI_NL_ALIGN(attribute->nla_len);
        if (aligned > remaining)
            return -EPROTO;
        remaining -= aligned;
        attribute = (struct nlattr *)((uint8_t *)attribute + aligned);
    }
    return -ENOENT;
}

int melodi_socket_open(struct melodi_socket *socket_state)
{
    struct sockaddr_nl address = { .nl_family = AF_NETLINK };
    socklen_t address_length = sizeof(address);
    int error;

    if (!socket_state)
        return -EINVAL;
    memset(socket_state, 0, sizeof(*socket_state));
    socket_state->descriptor = -1;
    socket_state->descriptor = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (socket_state->descriptor < 0)
        return -errno;
    if (bind(socket_state->descriptor, (struct sockaddr *)&address,
             sizeof(address)) < 0) {
        error = -errno;
        close(socket_state->descriptor);
        socket_state->descriptor = -1;
        return error;
    }
    if (getsockname(socket_state->descriptor, (struct sockaddr *)&address,
                    &address_length) < 0) {
        error = -errno;
        close(socket_state->descriptor);
        socket_state->descriptor = -1;
        return error;
    }
    socket_state->portid = address.nl_pid;
    error = melodi_resolve_family(socket_state);
    if (error) {
        close(socket_state->descriptor);
        socket_state->descriptor = -1;
    }
    return error;
}

void melodi_socket_close(struct melodi_socket *socket_state)
{
    if (socket_state && socket_state->descriptor >= 0) {
        close(socket_state->descriptor);
        socket_state->descriptor = -1;
    }
}

int melodi_socket_request(struct melodi_socket *socket_state, uint8_t command,
                          const uint8_t *attributes,
                          size_t attributes_length, uint16_t flags)
{
    uint8_t request[8192];
    struct melodi_genl_builder builder;
    int error;

    if (!socket_state || (!attributes && attributes_length) ||
        attributes_length > sizeof(request) -
        NLMSG_HDRLEN - GENL_HDRLEN)
        return -EINVAL;
    error = melodi_genl_begin(&builder, request, sizeof(request),
                              socket_state->family, flags,
                              ++socket_state->sequence,
                              socket_state->portid, command);
    if (error)
        return error;
    if (attributes_length) {
        memcpy(request + builder.length, attributes, attributes_length);
        builder.length += attributes_length;
    }
    melodi_genl_end(&builder);
    return melodi_send_buffer(socket_state, request, builder.length);
}

int melodi_socket_command(struct melodi_socket *socket_state, uint8_t command,
                          const uint8_t *attributes, size_t attributes_length,
                          bool expect_reply,
                          struct melodi_genl_message *reply,
                          uint8_t *reply_buffer, size_t reply_capacity)
{
    struct nlmsghdr *header;
    ssize_t received;
    int error;

    error = melodi_socket_request(socket_state, command, attributes,
                                  attributes_length,
                                  NLM_F_REQUEST | NLM_F_ACK);
    if (error)
        return error;
    for (;;) {
        received = melodi_receive_buffer(socket_state, reply_buffer,
                                         reply_capacity);
        if (received < 0)
            return received;
        if ((size_t)received < NLMSG_HDRLEN)
            return -EPROTO;
        header = (struct nlmsghdr *)reply_buffer;
        if (header->nlmsg_seq != socket_state->sequence)
            continue;
        if (header->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *netlink_error;

            if (header->nlmsg_len < NLMSG_LENGTH(sizeof(*netlink_error)))
                return -EPROTO;
            netlink_error = NLMSG_DATA(header);
            if (netlink_error->error)
                return netlink_error->error;
            return expect_reply ? -EPROTO : 0;
        }
        if (!expect_reply || header->nlmsg_type != socket_state->family)
            continue;
        return melodi_genl_parse(reply_buffer, header->nlmsg_len, reply);
    }
}
