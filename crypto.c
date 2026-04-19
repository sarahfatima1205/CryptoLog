/*
<<<<<<< HEAD
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
 *   Chain tamper detection: any block edit breaks its HMAC ? verify fails.
 */

#include "crypto.h"
#include "sha256.h"
=======
 * crypto.c  Key generation, signing, verification
 * No HAL UART dependency. Uses DWT for entropy (bare register).
 */

#include "crypto.h"
#include "sha256.h" //for block hashing
#include "ecc.h" //for key generation and digital signatures
#include "bignum.h" //for large no. operations used in ecc
>>>>>>> 56b3653d71a9506bf9a15f49ac228248589fe1e6
#include "stm32f4xx.h"
#include <string.h>
#include "uart_hw.h"

<<<<<<< HEAD
#define KEY_LEN 32

static uint8_t g_key[KEY_LEN];
static uint8_t g_pubkey[32];     /* SHA256(key) — public identity */
static int     g_initialized = 0;

/* -- Entropy: DWT cycle counter mixing ---------- */
static void collect_entropy(uint8_t out[32]) {
    /* Enable DWT cycle counter */
=======
static ECKeyPair g_keypair; //store device's keys
static int       g_initialized = 0; //flag to check if crypto is initialized before signing/verifying

//generate randomness/entropy on a microcontroller using timing jitter,compress into 32-byte value with SHA-256.
static void collect_entropy(uint8_t out[32]) {
    /* Enable DWT - data watchpoint and trace unit...counts cpu clock cycles */
>>>>>>> 56b3653d71a9506bf9a15f49ac228248589fe1e6
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0; //reset cycle counter
    DWT->CTRL  |= DWT_CTRL_CYCCNTENA_Msk;

    uint8_t raw[64];
    for (int i = 0; i < 64; i++) {
<<<<<<< HEAD
        volatile uint32_t t = DWT->CYCCNT;
        /* variable-length busy wait adds timing jitter */
        for (volatile int j = 0; j < (int)(t & 0x7F) + 16; j++);
        t ^= DWT->CYCCNT;
=======
        volatile uint32_t t = DWT->CYCCNT; //current cpu cycle count
        for (volatile int j = 0; j < (int)(t & 0xFF) + 10; j++); //variable delay--b/w 0 and 265 depends on last 8 digits of t
        t ^= DWT->CYCCNT; //new cycle count after delay, XOR with previous to get some randomness from jitter
        //scramble the bits so that patterns disappear hence more entropy
>>>>>>> 56b3653d71a9506bf9a15f49ac228248589fe1e6
        t ^= (t << 13);
        t ^= (t >> 7);
        t ^= (t << 17);
        raw[i] = (uint8_t)(t & 0xFF);
    }
<<<<<<< HEAD
    /* Compress into 32 bytes */
    sha256(raw, 64, out);
}

/* -- HMAC-SHA256 (RFC 2104) --------------------- */
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
=======
    sha256(raw, 64, out); //hash it to get 32 byte
}

/* -- RFC 6979 deterministic nonce -- */
//no. used once
static void rfc6979_nonce(uint8_t nonce[32],
                           const BN256 *priv,
                           const uint8_t hash[32]) {
    uint8_t priv_bytes[32];
    bn_to_bytes(priv, priv_bytes); //convert private key to bytes

    SHA256_CTX ctx; //start hashing
    sha256_init(&ctx); //1st input=private key and 2nd=message hash
    sha256_update(&ctx, priv_bytes, 32);
    sha256_update(&ctx, hash, 32);
    sha256_final(&ctx, nonce);
>>>>>>> 56b3653d71a9506bf9a15f49ac228248589fe1e6
}
//nonce = SHA256(priv_key || message_hash)

<<<<<<< HEAD
/* -- Public API --------------------------------- */

int crypto_init(void) {
    collect_entropy(g_key);
    /* Public identity = SHA256(secret_key) */
    sha256(g_key, KEY_LEN, g_pubkey);
    g_initialized = 1;
    return 0;
=======
//wallet creation
int crypto_init(void) {
    uint8_t seed[32];
    collect_entropy(seed);
    int r = ecc_keygen(&g_keypair, seed); //ecc key generation
    if (r == 0) g_initialized = 1;
    return r;
>>>>>>> 56b3653d71a9506bf9a15f49ac228248589fe1e6
}

void crypto_hash(const uint8_t *data, size_t len, uint8_t hash[32]) {
    sha256(data, len, hash);
}

<<<<<<< HEAD
int crypto_sign(const uint8_t hash[32], uint8_t sig[32]) {
    if (!g_initialized) return -1;
    hmac_sha256(g_key, KEY_LEN, hash, 32, sig);
=======
int crypto_sign(const uint8_t hash[32], uint8_t sig_out[64]) {
    if (!g_initialized) return -1; //fails if crypto not initialised
    uint8_t nonce[32];
    rfc6979_nonce(nonce, &g_keypair.priv, hash);
    ECDSASig sig;
    int r = ecdsa_sign(&sig, hash, &g_keypair.priv, nonce); //creates signature
    if (r != 0) return r; //error if signing fails
    ecdsa_sig_to_bytes(&sig, sig_out);
>>>>>>> 56b3653d71a9506bf9a15f49ac228248589fe1e6
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

<<<<<<< HEAD
void crypto_get_pubkey(uint8_t pub_out[32]) {
    memcpy(pub_out, g_pubkey, 32);
}
=======
void crypto_get_pubkey(uint8_t pub_out[65]) {
    ecc_export_pubkey(&g_keypair.pub, pub_out);
}

>>>>>>> 56b3653d71a9506bf9a15f49ac228248589fe1e6
