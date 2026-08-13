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
    struct melodi_node_id destination;
    struct melodi_socket socket_state = { .descriptor = -1 };
    unsigned long service;
    uint32_t flags = MELODI_F_AUTH_REQUIRED;
    uint32_t ifindex;
    int offset = 0;
    bool broadcast = false;
    const struct melodi_node_id *destination_ptr = &destination;
    char *end;
    int error;

    if (argc == 6 && strcmp(argv[1], "--broadcast") == 0) {
        flags |= MELODI_F_BROADCAST;
        broadcast = true;
        destination_ptr = NULL;
        offset = 1;
    } else if (argc == 7 && strcmp(argv[1], "--reliable") == 0) {
        flags |= MELODI_F_RELIABLE;
        offset = 1;
    } else if (argc == 7 && strcmp(argv[1], "--ordered") == 0) {
        flags |= MELODI_F_ORDERED;
        offset = 1;
    }
    if (argc != (broadcast ? 6 : 6 + offset) ||
        strcmp(argv[1 + offset], "-i") != 0) {
        fprintf(stderr,
                "usage: melsend [--reliable|--ordered] -i INTERFACE "
                "NODE_ID SERVICE MESSAGE\n"
                "       melsend --broadcast -i INTERFACE SERVICE MESSAGE\n");
        return 2;
    }
    ifindex = if_nametoindex(argv[2 + offset]);
    if (!ifindex) {
        fprintf(stderr, "melsend: %s\n", strerror(errno));
        return 1;
    }
    if (broadcast) {
        error = 0;
        service = strtoul(argv[3 + offset], &end, 10);
    } else {
        error = melodi_nodeid_parse(argv[3 + offset],
                                    strlen(argv[3 + offset]), &destination);
        service = strtoul(argv[4 + offset], &end, 10);
    }
    if (error || *end || service == 0 || service >= MELODI_SERVICE_ECHO) {
        fprintf(stderr, "melsend: invalid destination or service\n");
        return 2;
    }
    error = melodi_socket_open(&socket_state);
    if (!error)
        error = melodi_client_bind(&socket_state, ifindex, 49152);
    if (!error)
        error = melodi_client_send(
            &socket_state, destination_ptr, service,
            argv[broadcast ? 5 : 5 + offset],
            strlen(argv[broadcast ? 5 : 5 + offset]), flags, 1);
    melodi_socket_close(&socket_state);
    if (error) {
        fprintf(stderr, "melsend: %s\n", strerror(-error));
        return 1;
    }
    return 0;
}
