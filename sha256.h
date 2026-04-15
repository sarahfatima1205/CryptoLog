#ifndef SHA256_H
#define SHA256_H

/*
 * SHA-256 — from scratch, pure C, zero dependencies
 * Implements FIPS PUB 180-4
 *
 * Usage:
 *   SHA256_CTX ctx;
 *   sha256_init(&ctx);
 *   sha256_update(&ctx, data, len);
 *   sha256_final(&ctx, hash);   // hash = uint8_t[32]
 *
 * Or one-shot:
 *   sha256(data, len, hash);
 */

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[8];      /* H0..H7 */
    uint64_t bit_count;     /* total bits processed */
    uint8_t  buf[64];       /* pending block */
    uint32_t buf_len;       /* bytes in buf */
} SHA256_CTX;

void sha256_init   (SHA256_CTX *ctx);
void sha256_update (SHA256_CTX *ctx, const uint8_t *data, size_t len);
void sha256_final  (SHA256_CTX *ctx, uint8_t hash[32]);
void sha256        (const uint8_t *data, size_t len, uint8_t hash[32]);

#endif /* SHA256_H */
