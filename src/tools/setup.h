/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MELODI_SETUP_H
#define MELODI_SETUP_H

#include "nodeid.h"

#include <stddef.h>
#include <stdint.h>

#define MELODI_SETUP_MAX_OPERATIONS 130
#define MELODI_SETUP_PATH_MAX 4096

enum melodi_setup_operation_type {
    MELODI_SETUP_POLICY,
    MELODI_SETUP_SERVICE,
    MELODI_SETUP_BROADCAST,
    MELODI_SETUP_TRUST,
    MELODI_SETUP_BLOCK,
};

struct melodi_setup_operation {
    enum melodi_setup_operation_type type;
    struct melodi_node_id node_id;
    uint16_t service;
    uint8_t value;
};

struct melodi_setup_config {
    char identity_path[MELODI_SETUP_PATH_MAX];
    struct melodi_setup_operation operations[MELODI_SETUP_MAX_OPERATIONS];
    size_t operation_count;
};

int melodi_setup_parse(char *data, size_t length,
                       struct melodi_setup_config *config,
                       unsigned int *error_line);

#endif
