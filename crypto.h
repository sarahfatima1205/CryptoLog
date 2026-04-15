#ifndef CRYPTO_H
#define CRYPTO_H

/*
 * crypto.h — Top-level crypto API for STM32F429I-DISC1
 *
 * Wraps sha256 + ecc into a clean interface.
 * Handles key storage and entropy generation from hardware.
 */

#include <stdint.h>
#include <stddef.h>
#include "ecc.h"
#include "sha256.h"

/*
 * Call once at boot.
 * Generates keypair using DWT cycle counter + ADC noise as entropy.
 * Returns 0 on success.
 */
int crypto_init(void);

/* Hash len bytes of data into hash[32] */
void crypto_hash(const uint8_t *data, size_t len, uint8_t hash[32]);

/*
 * Sign hash[32].
 * Internally generates fresh deterministic nonce via RFC 6979 approach
 * (HMAC-SHA256 of priv || hash — no random needed, still secure).
 * sig_out[64] = R(32) || S(32)
 * Returns 0 on success.
 */
int crypto_sign(const uint8_t hash[32], uint8_t sig_out[64]);

/*
 * Verify sig[64] against hash[32] using stored public key.
 * Returns 0 if valid.
 */
int crypto_verify(const uint8_t hash[32], const uint8_t sig[64]);

/*
 * Get public key as 65 uncompressed bytes: 0x04 | X | Y
 */
void crypto_get_pubkey(uint8_t pub_out[65]);

#endif /* CRYPTO_H */
