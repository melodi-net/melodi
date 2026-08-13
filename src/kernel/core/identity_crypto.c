/* SPDX-License-Identifier: GPL-2.0-only */
#include "internal.h"

#include "crypto/monocypher-ed25519.h"

#include <keys/user-type.h>
#include <linux/errno.h>
#include <linux/key.h>
#include <linux/string.h>

int melodi_identity_key_matches(struct key *key,
                                const struct melodi_node_id *node_id)
{
    const struct user_key_payload *payload;
    u8 secret_key[64];
    u8 public_key[32];
    u8 seed[32];
    bool payload_valid;
    int error = -EKEYREJECTED;

    if (!key || !node_id || key->type != &key_type_user)
        return -EKEYREJECTED;
    down_read(&key->sem);
    payload = user_key_payload_locked(key);
    payload_valid = payload && payload->datalen == sizeof(seed);
    if (payload_valid)
        memcpy(seed, payload->data, sizeof(seed));
    else
        memset(seed, 0, sizeof(seed));
    up_read(&key->sem);
    if (!payload_valid)
        goto out;
    crypto_ed25519_key_pair(secret_key, public_key, seed);
    if (crypto_verify32(public_key, node_id->bytes + 1) == 0)
        error = 0;
out:
    crypto_wipe(seed, sizeof(seed));
    crypto_wipe(secret_key, sizeof(secret_key));
    crypto_wipe(public_key, sizeof(public_key));
    return error;
}

static int melodi_identity_secret(struct key *key, u8 secret_key[64])
{
    const struct user_key_payload *payload;
    u8 public_key[32];
    u8 seed[32];
    bool payload_valid;
    int error = -EKEYREJECTED;

    if (!key || key->type != &key_type_user)
        return -EKEYREJECTED;
    error = key_validate(key);
    if (error)
        return error;
    down_read(&key->sem);
    payload = user_key_payload_locked(key);
    payload_valid = payload && payload->datalen == sizeof(seed);
    if (payload_valid)
        memcpy(seed, payload->data, sizeof(seed));
    up_read(&key->sem);
    if (payload_valid) {
        crypto_ed25519_key_pair(secret_key, public_key, seed);
        error = 0;
    }
    crypto_wipe(seed, sizeof(seed));
    crypto_wipe(public_key, sizeof(public_key));
    return error;
}

int melodi_identity_sign(struct net_device *dev, const void *message,
                         size_t length, u8 signature[64])
{
    struct melodi_device *melodi = netdev_priv(dev);
    u8 secret_key[64];
    struct key *key;
    int error;

    if (!dev || (!message && length) || !signature ||
        length > MELODI_FRAME_MTU_MAX)
        return -EINVAL;
    mutex_lock(&melodi->lock);
    key = melodi->identity_key ? key_get(melodi->identity_key) : NULL;
    mutex_unlock(&melodi->lock);
    if (!key)
        return -ENOKEY;
    error = melodi_identity_secret(key, secret_key);
    key_put(key);
    if (!error)
        crypto_ed25519_sign(signature, secret_key, message, length);
    crypto_wipe(secret_key, sizeof(secret_key));
    return error;
}

int melodi_identity_verify(const struct melodi_node_id *node_id,
                           const void *message, size_t length,
                           const u8 signature[64])
{
    if (!node_id || (!message && length) || !signature ||
        length > MELODI_FRAME_MTU_MAX ||
        node_id->bytes[0] != MELODI_NODE_ID_SCHEME_ED25519)
        return -EINVAL;
    return crypto_ed25519_check(signature, node_id->bytes + 1,
                                message, length) == 0 ? 0 : -EKEYREJECTED;
}
