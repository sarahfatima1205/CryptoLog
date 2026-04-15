/*
 * crypto.c — Key generation, signing, verification
 * No HAL UART dependency. Uses DWT for entropy (bare register).
 */

#include "crypto.h"
#include "sha256.h"
#include "ecc.h"
#include "bignum.h"
#include "stm32f4xx.h"
#include <string.h>

static ECKeyPair g_keypair;
static int       g_initialized = 0;

/* -- Entropy from DWT cycle counter -- */
static void collect_entropy(uint8_t out[32]) {
    /* Enable DWT */
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL  |= DWT_CTRL_CYCCNTENA_Msk;

    uint8_t raw[64];
    for (int i = 0; i < 64; i++) {
        volatile uint32_t t = DWT->CYCCNT;
        for (volatile int j = 0; j < (int)(t & 0xFF) + 10; j++);
        t ^= DWT->CYCCNT;
        t ^= (t << 13);
        t ^= (t >> 7);
        t ^= (t << 17);
        raw[i] = (uint8_t)(t & 0xFF);
    }
    sha256(raw, 64, out);
}

/* -- RFC 6979 deterministic nonce -- */
static void rfc6979_nonce(uint8_t nonce[32],
                           const BN256 *priv,
                           const uint8_t hash[32]) {
    uint8_t priv_bytes[32];
    bn_to_bytes(priv, priv_bytes);

    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, priv_bytes, 32);
    sha256_update(&ctx, hash, 32);
    sha256_final(&ctx, nonce);
}

int crypto_init(void) {
    uint8_t seed[32];
    collect_entropy(seed);
    int r = ecc_keygen(&g_keypair, seed);
    if (r == 0) g_initialized = 1;
    return r;
}

void crypto_hash(const uint8_t *data, size_t len, uint8_t hash[32]) {
    sha256(data, len, hash);
}

int crypto_sign(const uint8_t hash[32], uint8_t sig_out[64]) {
    if (!g_initialized) return -1;
    uint8_t nonce[32];
    rfc6979_nonce(nonce, &g_keypair.priv, hash);
    ECDSASig sig;
    int r = ecdsa_sign(&sig, hash, &g_keypair.priv, nonce);
    if (r != 0) return r;
    ecdsa_sig_to_bytes(&sig, sig_out);
    return 0;
}

int crypto_verify(const uint8_t hash[32], const uint8_t sig[64]) {
    if (!g_initialized) return -1;
    ECDSASig s;
    ecdsa_sig_from_bytes(&s, sig);
    return ecdsa_verify(&s, hash, &g_keypair.pub);
}

void crypto_get_pubkey(uint8_t pub_out[65]) {
    ecc_export_pubkey(&g_keypair.pub, pub_out);
}
