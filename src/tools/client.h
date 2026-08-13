/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MELODI_CLIENT_H
#define MELODI_CLIENT_H

#include "netlink.h"
#include "nodeid.h"

struct melodi_received_message {
    struct melodi_node_id source;
    uint16_t source_service;
    uint16_t local_service;
    const uint8_t *payload;
    size_t payload_length;
};

int melodi_client_bind(struct melodi_socket *socket_state, uint32_t ifindex,
                       uint16_t service);
int melodi_client_send(struct melodi_socket *socket_state,
                       const struct melodi_node_id *destination,
                       uint16_t destination_service, const void *payload,
                       size_t payload_length, uint32_t flags, uint64_t cookie);
int melodi_client_receive(struct melodi_socket *socket_state, void *buffer,
                          size_t capacity,
                          struct melodi_received_message *message);

#endif
