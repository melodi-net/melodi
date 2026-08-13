/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MELODI_TOOL_NETLINK_H
#define MELODI_TOOL_NETLINK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "genl.h"

struct melodi_socket {
    int descriptor;
    uint16_t family;
    uint32_t portid;
    uint32_t sequence;
};

int melodi_socket_open(struct melodi_socket *socket_state);
void melodi_socket_close(struct melodi_socket *socket_state);
int melodi_socket_request(struct melodi_socket *socket_state, uint8_t command,
                          const uint8_t *attributes,
                          size_t attributes_length, uint16_t flags);
int melodi_socket_command(struct melodi_socket *socket_state, uint8_t command,
                          const uint8_t *attributes, size_t attributes_length,
                          bool expect_reply,
                          struct melodi_genl_message *reply,
                          uint8_t *reply_buffer, size_t reply_capacity);

#endif
