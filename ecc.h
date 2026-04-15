#ifndef ECC_H
#define ECC_H

/*
 * ecc.h — ECDSA on NIST P-256 (secp256r1) from scratch
 * Pure C, no dependencies except bignum.h and sha256.h
 *
 * Curve equation: y² = x³ - 3x + b  (mod p)
 * Points are in affine coordinates (x, y).
 *
 * Public API:
 *   ecc_keygen()    — generate private + public key
 *   ecdsa_sign()    — sign a 32-byte hash
 *   ecdsa_verify()  — verify a signature
 */

#include "bignum.h"

/* -- Elliptic curve point (affine) ------------ */
typedef struct {
    BN256 x;
    BN256 y;
    int   infinity;   /* 1 = point at infinity (identity) */
} ECPoint;

/* -- Key pair --------------------------------- */
typedef struct {
    BN256   priv;      /* private key: random k in [1, n-1] */
    ECPoint pub;       /* public key: Q = k * G */
} ECKeyPair;

/* -- ECDSA signature -------------------------- */
typedef struct {
    BN256 r;
    BN256 s;
} ECDSASig;

/* -- Public API ------------------------------- */

/*
 * Generate keypair.
 * seed[32]: 32 bytes of entropy (from DWT noise or any source)
 * Returns 0 on success.
 */
int ecc_keygen(ECKeyPair *kp, const uint8_t seed[32]);

/*
 * Sign hash[32] using private key.
 * nonce[32]: fresh random 32 bytes (MUST be unique per signature!)
 * Returns 0 on success.
 */
int ecdsa_sign(ECDSASig *sig,
               const uint8_t hash[32],
               const BN256 *priv,
               const uint8_t nonce[32]);

/*
 * Verify signature against hash and public key.
 * Returns 0 if valid, -1 if invalid.
 */
int ecdsa_verify(const ECDSASig *sig,
                 const uint8_t hash[32],
                 const ECPoint *pub);

/*
 * Export public key as 65 uncompressed bytes:
 * 0x04 | X(32 big-endian) | Y(32 big-endian)
 */
void ecc_export_pubkey(const ECPoint *pub, uint8_t out[65]);

/*
 * Import public key from 65 uncompressed bytes.
 * Returns 0 on success.
 */
int ecc_import_pubkey(ECPoint *pub, const uint8_t in[65]);

/*
 * Serialize/deserialize signature to/from 64 raw bytes: R(32) | S(32)
 */
void ecdsa_sig_to_bytes  (const ECDSASig *sig, uint8_t out[64]);
int  ecdsa_sig_from_bytes(ECDSASig *sig, const uint8_t in[64]);

#endif /* ECC_H */
