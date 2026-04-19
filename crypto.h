#ifndef CRYPTO_H
#define CRYPTO_H

/*
 * crypto.h — HMAC-SHA256 signing, from scratch
 *
 * Replaces ECDSA which is too slow at 16MHz for interactive use.
 * HMAC-SHA256 provides:
 *   - Message authentication (tamper detection)
 *   - Keyed signing (secret key on device)
 *   - Fast: <1ms per operation at 16MHz
 *
 * Key is derived from DWT entropy at boot, stored in RAM.
 * Signature = HMAC-SHA256(key, hash) = 32 bytes.
 *
 * Verification: recompute HMAC and compare.
 * Public key: SHA256(secret_key) — a commitment, not the key itself.
 */

#include <stdint.h>
#include <stddef.h>

/* Call once at boot. Generates secret key from hardware entropy. */
int  crypto_init(void);

/* Hash data into hash[32] using SHA-256 */
void crypto_hash(const uint8_t *data, size_t len, uint8_t hash[32]);

/* Sign hash[32] ? sig[32] using HMAC-SHA256 with device secret key */
int  crypto_sign(const uint8_t hash[32], uint8_t sig[32]);

/* Verify sig[32] against hash[32]. Returns 0 if valid. */
int  crypto_verify(const uint8_t hash[32], const uint8_t sig[32]);

/*
 * Get device public identity: SHA256(secret_key)
 * This is a commitment to the key — proves same device signed,
 * without revealing the key. 32 bytes.
 */
void crypto_get_pubkey(uint8_t pub_out[32]);

#endif