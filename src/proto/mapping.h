/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MELODI_MAPPING_H
#define MELODI_MAPPING_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#include <stdint.h>
#endif

#include "melodi.h"

#define MELODI_MESH_DOMAIN_SIZE 32
#define MELODI_MAPPING_VERSION 1
#define MELODI_NATIVE_LOCATOR_INVALID 0U
#define MELODI_NATIVE_LOCATOR_BROADCAST (~0U)
#define MELODI_MAPPING_SET_LIMIT 64

struct melodi_mapping_entry {
    struct melodi_node_id node_id;
#ifdef __KERNEL__
    u32 native_locator;
    u32 collision_round;
#else
    uint32_t native_locator;
    uint32_t collision_round;
#endif
};

#ifdef __KERNEL__
int melodi_map_native_locator(const u8 domain[MELODI_MESH_DOMAIN_SIZE],
                              const struct melodi_node_id *node_id,
                              u32 first_round, u32 *native_locator,
                              u32 *selected_round);
int melodi_map_native_locator_available(
    const u8 domain[MELODI_MESH_DOMAIN_SIZE],
    const struct melodi_node_id *node_id, u32 first_round,
    const u32 *occupied, size_t occupied_count, u32 *native_locator,
    u32 *selected_round);
int melodi_resolve_collision_set(
    const u8 domain[MELODI_MESH_DOMAIN_SIZE],
    const struct melodi_node_id *nodes, size_t count,
    struct melodi_mapping_entry *entries);
#else
int melodi_map_native_locator(
    const uint8_t domain[MELODI_MESH_DOMAIN_SIZE],
    const struct melodi_node_id *node_id,
    uint32_t first_round, uint32_t *native_locator,
    uint32_t *selected_round);
int melodi_map_native_locator_available(
    const uint8_t domain[MELODI_MESH_DOMAIN_SIZE],
    const struct melodi_node_id *node_id, uint32_t first_round,
    const uint32_t *occupied, size_t occupied_count,
    uint32_t *native_locator,
    uint32_t *selected_round);
int melodi_resolve_collision_set(
    const uint8_t domain[MELODI_MESH_DOMAIN_SIZE],
    const struct melodi_node_id *nodes, size_t count,
    struct melodi_mapping_entry *entries);
#endif

#endif
