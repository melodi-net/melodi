/* SPDX-License-Identifier: GPL-2.0-only */
#include "client.h"

#include <errno.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    uint8_t buffer[8192];
    struct melodi_received_message received;
    struct melodi_node_id destination;
    struct melodi_socket socket_state = { .descriptor = -1 };
    unsigned long local_service;
    unsigned long destination_service;
    unsigned int ifindex;
    char source[MELODI_NODE_ID_STRING_SIZE];
    char *end;
    int error;

    if (argc != 6) {
        fprintf(stderr, "usage: %s INTERFACE LOCAL_SERVICE NODE_ID SERVICE MESSAGE\n",
                argv[0]);
        return 2;
    }
    ifindex = if_nametoindex(argv[1]);
    local_service = strtoul(argv[2], &end, 10);
    if (!ifindex || *end || local_service == 0 ||
        local_service >= MELODI_SERVICE_ECHO)
        return 2;
    error = melodi_nodeid_parse(argv[3], strlen(argv[3]), &destination);
    destination_service = strtoul(argv[4], &end, 10);
    if (error || *end || destination_service == 0 ||
        destination_service >= MELODI_SERVICE_ECHO)
        return 2;
    error = melodi_socket_open(&socket_state);
    if (!error)
        error = melodi_client_bind(&socket_state, ifindex, local_service);
    if (!error)
        error = melodi_client_send(&socket_state, &destination,
                                   destination_service, argv[5],
                                   strlen(argv[5]), MELODI_F_AUTH_REQUIRED, 1);
    if (!error)
        error = melodi_client_receive(&socket_state, buffer, sizeof(buffer),
                                      &received);
    if (!error)
        error = melodi_nodeid_format(&received.source, source);
    if (!error)
        printf("%s %u: %.*s\n", source, received.source_service,
               (int)received.payload_length, (const char *)received.payload);
    melodi_socket_close(&socket_state);
    if (error)
        fprintf(stderr, "%s: %s\n", argv[0], strerror(-error));
    return error ? 1 : 0;
}
