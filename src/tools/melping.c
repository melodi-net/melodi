/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include "client.h"

#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define MELODI_PING_ATTEMPTS 3
#define MELODI_PING_TIMEOUT_MS 10000
#define MELODI_PING_TIMEOUT_MAX_MS 120000
#define MELODI_PING_ROUND_TRIPS 3

static long long melodi_ping_now_us(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        return -1;
    return (long long)now.tv_sec * 1000000LL + now.tv_nsec / 1000;
}

/* A probe outlives several link round trips, however slow the link. */
static int melodi_ping_timeout(struct melodi_socket *socket_state,
                               uint32_t ifindex, unsigned int *timeout_ms)
{
    uint8_t attributes_buffer[64];
    uint8_t reply_buffer[4096];
    struct melodi_genl_builder attributes;
    struct melodi_genl_message reply;
    unsigned long long scaled;
    uint32_t pace_us = 0;
    int error;

    *timeout_ms = MELODI_PING_TIMEOUT_MS;
    error = melodi_genl_begin(&attributes, attributes_buffer,
                              sizeof(attributes_buffer), socket_state->family,
                              0, 0, socket_state->portid,
                              MELODI_CMD_LINK_GET);
    if (!error)
        error = melodi_genl_put_u32(&attributes, MELODI_A_IFINDEX, ifindex);
    if (error)
        return error;
    error = melodi_socket_command(
        socket_state, MELODI_CMD_LINK_GET,
        attributes.data + NLMSG_HDRLEN + GENL_HDRLEN,
        attributes.length - NLMSG_HDRLEN - GENL_HDRLEN, true, &reply,
        reply_buffer, sizeof(reply_buffer));
    if (error)
        return error;
    if (!reply.attributes[MELODI_A_FRAME_PACE_US] ||
        reply.lengths[MELODI_A_FRAME_PACE_US] != sizeof(pace_us))
        return 0;
    memcpy(&pace_us, reply.attributes[MELODI_A_FRAME_PACE_US],
           sizeof(pace_us));
    scaled = (unsigned long long)pace_us / 1000 * MELODI_PING_ROUND_TRIPS;
    if (scaled > MELODI_PING_TIMEOUT_MAX_MS)
        scaled = MELODI_PING_TIMEOUT_MAX_MS;
    if (scaled > *timeout_ms)
        *timeout_ms = (unsigned int)scaled;
    return 0;
}

int main(int argc, char **argv)
{
    uint8_t receive_buffer[MELODI_MESSAGE_MTU + 512];
    struct melodi_received_message message;
    struct melodi_node_id destination;
    struct melodi_socket socket_state = { .descriptor = -1 };
    struct pollfd descriptor;
    unsigned int timeout_ms = MELODI_PING_TIMEOUT_MS;
    long long started;
    long long finished = 0;
    uint64_t nonce;
    uint32_t ifindex;
    unsigned int attempt;
    bool replied = false;
    int error;

    if (argc != 4 || strcmp(argv[1], "-i") != 0) {
        fprintf(stderr, "usage: melping -i INTERFACE NODE_ID\n");
        return 2;
    }
    ifindex = if_nametoindex(argv[2]);
    error = ifindex ? 0 : -errno;
    if (!error)
        error = melodi_nodeid_parse(argv[3], strlen(argv[3]), &destination);
    started = melodi_ping_now_us();
    if (!error && started < 0)
        error = -errno;
    nonce = (uint64_t)started;
    if (!error)
        error = melodi_socket_open(&socket_state);
    if (!error)
        error = melodi_ping_timeout(&socket_state, ifindex, &timeout_ms);
    if (!error)
        error = melodi_client_bind(&socket_state, ifindex, 49153);
    descriptor.fd = socket_state.descriptor;
    descriptor.events = POLLIN;
    descriptor.revents = 0;
    /* The radio link is lossy, so an unanswered probe is resent. */
    for (attempt = 0; !error && !replied && attempt < MELODI_PING_ATTEMPTS;
         attempt++) {
        long long deadline;

        error = melodi_client_send(
            &socket_state, &destination, MELODI_SERVICE_ECHO, &nonce,
            sizeof(nonce), MELODI_F_AUTH_REQUIRED, nonce);
        if (error)
            break;
        deadline = melodi_ping_now_us();
        if (deadline < 0) {
            error = -errno;
            break;
        }
        deadline += (long long)timeout_ms * 1000LL;
        while (!error && !replied) {
            long long remaining = melodi_ping_now_us();
            int ready;

            if (remaining < 0) {
                error = -errno;
                break;
            }
            remaining = (deadline - remaining) / 1000;
            if (remaining <= 0)
                break;
            ready = poll(&descriptor, 1, (int)remaining);
            if (ready < 0) {
                error = -errno;
                break;
            }
            if (!ready)
                break;
            error = melodi_client_receive(&socket_state, receive_buffer,
                                          sizeof(receive_buffer), &message);
            if (error)
                break;
            if (!memcmp(&message.source, &destination, sizeof(destination)) &&
                message.source_service == MELODI_SERVICE_ECHO &&
                message.local_service == 49153 &&
                message.payload_length == sizeof(nonce) &&
                !memcmp(message.payload, &nonce, sizeof(nonce)))
                replied = true;
        }
    }
    if (!error && !replied)
        error = -ETIMEDOUT;
    if (!error) {
        finished = melodi_ping_now_us();
        if (finished < 0)
            error = -errno;
    }
    melodi_socket_close(&socket_state);
    if (error) {
        fprintf(stderr, "melping: %s\n", strerror(-error));
        return 1;
    }
    printf("reply from %s: %.3f ms\n", argv[3],
           (finished - started) / 1000.0);
    return 0;
}
