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
    struct melodi_received_message message;
    struct melodi_socket socket_state;
    unsigned long service;
    uint32_t ifindex;
    char text[MELODI_NODE_ID_STRING_SIZE];
    char *end;
    int error;

    if (argc != 4 || strcmp(argv[1], "-i") != 0) {
        fprintf(stderr, "usage: melrecv -i INTERFACE SERVICE\n");
        return 2;
    }
    ifindex = if_nametoindex(argv[2]);
    service = strtoul(argv[3], &end, 10);
    if (!ifindex || *end || service == 0 || service >= MELODI_SERVICE_ECHO) {
        fprintf(stderr, "melrecv: invalid interface or service\n");
        return 2;
    }
    error = melodi_socket_open(&socket_state);
    if (!error)
        error = melodi_client_bind(&socket_state, ifindex, service);
    if (!error)
        error = melodi_client_receive(&socket_state, buffer, sizeof(buffer),
                                      &message);
    if (!error)
        error = melodi_nodeid_format(&message.source, text);
    if (!error) {
        fprintf(stderr, "%s %u\n", text, message.source_service);
        if ((message.payload_length &&
             fwrite(message.payload, message.payload_length, 1, stdout) != 1) ||
            fputc('\n', stdout) == EOF)
            error = -EIO;
    }
    melodi_socket_close(&socket_state);
    if (error) {
        fprintf(stderr, "melrecv: %s\n", strerror(-error));
        return 1;
    }
    return 0;
}
