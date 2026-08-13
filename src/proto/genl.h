/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MELODI_GENL_H
#define MELODI_GENL_H

#include <stddef.h>
#include <stdint.h>

#include "melodi.h"

struct melodi_genl_builder {
    uint8_t *data;
    size_t capacity;
    size_t length;
};

struct melodi_genl_message {
    uint16_t family;
    uint16_t flags;
    uint32_t sequence;
    uint32_t portid;
    uint8_t command;
    const void *attributes[MELODI_A_MAX + 1];
    uint16_t lengths[MELODI_A_MAX + 1];
};

int melodi_genl_begin(struct melodi_genl_builder *builder, void *buffer,
                      size_t capacity, uint16_t family, uint16_t flags,
                      uint32_t sequence, uint32_t portid, uint8_t command);
int melodi_genl_put(struct melodi_genl_builder *builder, uint16_t type,
                    const void *value, uint16_t length);
int melodi_genl_put_u8(struct melodi_genl_builder *builder, uint16_t type,
                       uint8_t value);
int melodi_genl_put_u16(struct melodi_genl_builder *builder, uint16_t type,
                        uint16_t value);
int melodi_genl_put_u32(struct melodi_genl_builder *builder, uint16_t type,
                        uint32_t value);
int melodi_genl_put_u64(struct melodi_genl_builder *builder, uint16_t type,
                        uint64_t value);
int melodi_genl_end(struct melodi_genl_builder *builder);
int melodi_genl_parse(const void *buffer, size_t length,
                      struct melodi_genl_message *message);

#endif
