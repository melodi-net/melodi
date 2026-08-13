/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MELODI_TPM_H
#define MELODI_TPM_H

#include <stddef.h>
#include <stdint.h>

int melodi_tpm_provision(const char *directory, uint32_t parent_handle,
                         uint32_t counter_handle, const char *owner_auth_path,
                         const uint8_t private_key[32]);
int melodi_tpm_reserve(const char *directory, uint8_t private_key[32],
                       uint32_t *generation);

#endif
