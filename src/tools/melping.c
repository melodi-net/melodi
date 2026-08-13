/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include "client.h"

#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(int argc, char **argv)
{
    uint8_t receive_buffer[MELODI_MESSAGE_MTU + 512];
    struct melodi_received_message message;
    struct melodi_node_id destination;
    struct melodi_socket socket_state = { .descriptor = -1 };
    struct timespec started = { 0 };
    struct timespec finished = { 0 };
    struct pollfd descriptor;
    uint64_t nonce;
    uint32_t ifindex;
    long long elapsed_us;
    int error;

    if (argc != 4 || strcmp(argv[1], "-i") != 0) {
        fprintf(stderr, "usage: melping -i INTERFACE NODE_ID\n");
        return 2;
    }
    ifindex = if_nametoindex(argv[2]);
    error = ifindex ? 0 : -errno;
    if (!error)
        error = melodi_nodeid_parse(argv[3], strlen(argv[3]), &destination);
    if (!error && clock_gettime(CLOCK_MONOTONIC, &started) < 0)
        error = -errno;
    nonce = (uint64_t)started.tv_sec * 1000000000ULL + started.tv_nsec;
    if (!error)
        error = melodi_socket_open(&socket_state);
    if (!error)
        error = melodi_client_bind(&socket_state, ifindex, 49153);
    if (!error)
        error = melodi_client_send(
            &socket_state, &destination, MELODI_SERVICE_ECHO, &nonce,
            sizeof(nonce), MELODI_F_AUTH_REQUIRED, nonce);
    descriptor.fd = socket_state.descriptor;
    descriptor.events = POLLIN;
    descriptor.revents = 0;
    if (!error) {
        int ready = poll(&descriptor, 1, 10000);

        error = ready < 0 ? -errno : (ready == 0 ? -ETIMEDOUT : 0);
    }
    if (!error)
        error = melodi_client_receive(&socket_state, receive_buffer,
                                      sizeof(receive_buffer), &message);
    if (!error &&
        (memcmp(&message.source, &destination, sizeof(destination)) ||
         message.source_service != MELODI_SERVICE_ECHO ||
         message.local_service != 49153 ||
         message.payload_length != sizeof(nonce) ||
         memcmp(message.payload, &nonce, sizeof(nonce))))
        error = -EPROTO;
    if (!error && clock_gettime(CLOCK_MONOTONIC, &finished) < 0)
        error = -errno;
    melodi_socket_close(&socket_state);
    if (error) {
        fprintf(stderr, "melping: %s\n", strerror(-error));
        return 1;
    }
    elapsed_us = (finished.tv_sec - started.tv_sec) * 1000000LL +
                 (finished.tv_nsec - started.tv_nsec) / 1000;
    printf("reply from %s: %.3f ms\n", argv[3], elapsed_us / 1000.0);
    return 0;
}
