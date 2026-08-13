// SPDX-License-Identifier: CC0-1.0
#ifndef ED25519_H
#define ED25519_H

#include "monocypher.h"

#ifdef MONOCYPHER_CPP_NAMESPACE
namespace MONOCYPHER_CPP_NAMESPACE {
#elif defined(__cplusplus)
extern "C" {
#endif







typedef struct {
	uint64_t hash[8];
	uint64_t input[16];
	uint64_t input_size[2];
	size_t   input_idx;
} crypto_sha512_ctx;

typedef struct {
	uint8_t key[128];
	crypto_sha512_ctx ctx;
} crypto_sha512_hmac_ctx;




void crypto_sha512_init  (crypto_sha512_ctx *ctx);
void crypto_sha512_update(crypto_sha512_ctx *ctx,
                          const uint8_t *message, size_t  message_size);
void crypto_sha512_final (crypto_sha512_ctx *ctx, uint8_t hash[64]);
void crypto_sha512(uint8_t hash[64],
                   const uint8_t *message, size_t message_size);



void crypto_sha512_hmac_init(crypto_sha512_hmac_ctx *ctx,
                             const uint8_t *key, size_t key_size);
void crypto_sha512_hmac_update(crypto_sha512_hmac_ctx *ctx,
                               const uint8_t *message, size_t  message_size);
void crypto_sha512_hmac_final(crypto_sha512_hmac_ctx *ctx, uint8_t hmac[64]);
void crypto_sha512_hmac(uint8_t hmac[64],
                        const uint8_t *key    , size_t key_size,
                        const uint8_t *message, size_t message_size);



void crypto_sha512_hkdf_expand(uint8_t       *okm,  size_t okm_size,
                               const uint8_t *prk,  size_t prk_size,
                               const uint8_t *info, size_t info_size);
void crypto_sha512_hkdf(uint8_t       *okm , size_t okm_size,
                        const uint8_t *ikm , size_t ikm_size,
                        const uint8_t *salt, size_t salt_size,
                        const uint8_t *info, size_t info_size);





void crypto_ed25519_key_pair(uint8_t secret_key[64],
                             uint8_t public_key[32],
                             uint8_t seed[32]);
void crypto_ed25519_sign(uint8_t        signature [64],
                         const uint8_t  secret_key[64],
                         const uint8_t *message, size_t message_size);
int crypto_ed25519_check(const uint8_t  signature [64],
                         const uint8_t  public_key[32],
                         const uint8_t *message, size_t message_size);


void crypto_ed25519_ph_sign(uint8_t       signature   [64],
                            const uint8_t secret_key  [64],
                            const uint8_t message_hash[64]);
int crypto_ed25519_ph_check(const uint8_t signature   [64],
                            const uint8_t public_key  [32],
                            const uint8_t message_hash[64]);

#ifdef __cplusplus
}
#endif

#endif

