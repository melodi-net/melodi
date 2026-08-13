/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MELODI_NODEID_H
#define MELODI_NODEID_H

#include <stddef.h>

#include "melodi.h"

enum melodi_nodeid_result {
    MELODI_NODEID_OK = 0,
    MELODI_NODEID_INVALID = -1,
    MELODI_NODEID_LENGTH = -2,
    MELODI_NODEID_SCHEME = -3,
    MELODI_NODEID_ENCODING = -4,
    MELODI_NODEID_KEY = -5,
};

int melodi_nodeid_validate(const struct melodi_node_id *node);
int melodi_nodeid_format(const struct melodi_node_id *node,
                         char output[MELODI_NODE_ID_STRING_SIZE]);
int melodi_nodeid_parse(const char *text, size_t length,
                        struct melodi_node_id *node);

#endif
