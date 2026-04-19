/*
 * crypto.c — HMAC-SHA256 signing from scratch
 *
 * HMAC(key, msg) = SHA256( (key XOR opad) || SHA256( (key XOR ipad) || msg ) )
 * ipad = 0x36 repeated, opad = 0x5C repeated  (RFC 2104)
 *
 * Why HMAC instead of ECC:
 *   ECC P-256 scalar_mul = ~256 point doublings, each needing bn_mod_inv
 *   bn_mod_inv = binary GCD = ~512 iterations of 256-bit arithmetic
 *   At 16MHz: ~30-60 seconds per sign. Unusable.
 *
 *   HMAC-SHA256 = 2x SHA-256 = ~2000 operations. At 16MHz: <5ms. Fast.
 *
 * Security model:
 *   Secret key lives in RAM. Generated fresh each boot from DWT entropy.
 *   Attacker without key cannot forge HMAC signatures.
 *   Chain tamper detection: any block edit breaks its HMAC → verify fails.
 */

#include "crypto.h"
#include "sha256.h"
#include "stm32f4xx.h"
#include <string.h>

#define KEY_LEN 32

static uint8_t g_key[KEY_LEN];
static uint8_t g_pubkey[32];     /* SHA256(key) — public identity */
static int     g_initialized = 0;

/* ── Entropy: DWT cycle counter mixing ────────── */
static void collect_entropy(uint8_t out[32]) {
    /* Enable DWT cycle counter */
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL  |= DWT_CTRL_CYCCNTENA_Msk;

    uint8_t raw[64];
    for (int i = 0; i < 64; i++) {
        volatile uint32_t t = DWT->CYCCNT;
        /* variable-length busy wait adds timing jitter */
        for (volatile int j = 0; j < (int)(t & 0x7F) + 16; j++);
        t ^= DWT->CYCCNT;
        t ^= (t << 13);
        t ^= (t >> 7);
        t ^= (t << 17);
        raw[i] = (uint8_t)(t & 0xFF);
    }
    /* Compress into 32 bytes */
    sha256(raw, 64, out);
}

/* ── HMAC-SHA256 (RFC 2104) ───────────────────── */
static void hmac_sha256(const uint8_t *key,  size_t key_len,
                         const uint8_t *msg,  size_t msg_len,
                         uint8_t        out[32]) {
    uint8_t k_ipad[64], k_opad[64];
    uint8_t inner[32];

    /* Keys longer than 64 bytes are hashed first */
    uint8_t k[64];
    memset(k, 0, 64);
    if (key_len > 64) {
        sha256(key, key_len, k);
    } else {
        memcpy(k, key, key_len);
    }

    /* XOR key with ipad / opad */
    for (int i = 0; i < 64; i++) {
        k_ipad[i] = k[i] ^ 0x36;
        k_opad[i] = k[i] ^ 0x5C;
    }

    /* Inner hash: SHA256(k_ipad || msg) */
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64);
    sha256_update(&ctx, msg,    msg_len);
    sha256_final(&ctx, inner);

    /* Outer hash: SHA256(k_opad || inner) */
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64);
    sha256_update(&ctx, inner,  32);
    sha256_final(&ctx, out);
}

/* ── Public API ───────────────────────────────── */

int crypto_init(void) {
    collect_entropy(g_key);
    /* Public identity = SHA256(secret_key) */
    sha256(g_key, KEY_LEN, g_pubkey);
    g_initialized = 1;
    return 0;
}

void crypto_hash(const uint8_t *data, size_t len, uint8_t hash[32]) {
    sha256(data, len, hash);
}

int crypto_sign(const uint8_t hash[32], uint8_t sig[32]) {
    if (!g_initialized) return -1;
    hmac_sha256(g_key, KEY_LEN, hash, 32, sig);
    return 0;
}

int crypto_verify(const uint8_t hash[32], const uint8_t sig[32]) {
    if (!g_initialized) return -1;
    uint8_t expected[32];
    hmac_sha256(g_key, KEY_LEN, hash, 32, expected);
    /* Constant-time comparison to prevent timing attacks */
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= expected[i] ^ sig[i];
    return diff ? -1 : 0;
}

void crypto_get_pubkey(uint8_t pub_out[32]) {
    memcpy(pub_out, g_pubkey, 32);
}