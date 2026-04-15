/*
 * ecc.c — NIST P-256 ECDSA from scratch, pure C
 *
 * Implements:
 *  - Affine point addition and doubling
 *  - Scalar multiplication via double-and-add
 *  - ECDSA sign and verify
 *
 * Every formula comes from:
 *  SEC1 v2.0 (Certicom) and
 *  NIST FIPS 186-4
 *
 * Evaluator explanation:
 *  P-256 is an elliptic curve defined over a prime field F_p.
 *  Points form a group under geometric addition.
 *  Private key = scalar k. Public key = k * G (base point).
 *  ECDSA signature: given hash e, pick nonce r_k, compute:
 *    R = r_k * G, r = R.x mod n
 *    s = r_k^-1 * (e + priv * r) mod n
 *  Verify: u1 = e/s mod n, u2 = r/s mod n, check (u1*G + u2*Q).x == r
 */

#include "ecc.h"
#include "sha256.h"
#include <string.h>

/* -----------------------------------------------
 * P-256 domain parameters
 * ----------------------------------------------- */

/* Base point G */
static const BN256 G_X = {{
    0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81,
    0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2
}};
static const BN256 G_Y = {{
    0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357,
    0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2
}};

/* Curve parameter b */
static const BN256 P256_B = {{
    0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0,
    0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8
}};

/* -----------------------------------------------
 * Affine point arithmetic on P-256
 *
 * Addition formulas (short Weierstrass, a=-3):
 *  ? = (y2 - y1) / (x2 - x1) mod p
 *  x3 = ?² - x1 - x2 mod p
 *  y3 = ?(x1 - x3) - y1 mod p
 *
 * Doubling formulas:
 *  ? = (3x1² + a) / (2y1) mod p   (a = -3 for P-256)
 *  x3 = ?² - 2x1 mod p
 *  y3 = ?(x1 - x3) - y1 mod p
 * ----------------------------------------------- */

static void point_copy(ECPoint *r, const ECPoint *a) {
    bn_copy(&r->x, &a->x);
    bn_copy(&r->y, &a->y);
    r->infinity = a->infinity;
}

/* r = a + b on P-256 */
static void point_add(ECPoint *r, const ECPoint *a, const ECPoint *b) {
    if (a->infinity) { point_copy(r, b); return; }
    if (b->infinity) { point_copy(r, a); return; }

    /* Check if a == b (use doubling) or a == -b (return infinity) */
    if (bn_cmp(&a->x, &b->x) == 0) {
        if (bn_cmp(&a->y, &b->y) == 0) {
            /* a == b: double */
            BN256 lam, tmp, x3, y3;

            /* lam = (3*x1^2 - 3) / (2*y1) mod p
             * Since a = -3: 3*x1^2 + a = 3*(x1^2 - 1) */
            BN256 x1sq;
            bn_mod_mul(&x1sq, &a->x, &a->x, &P256_P);        /* x1^2 */

            BN256 three; bn_set_u32(&three, 3);
            BN256 numer;
            bn_mod_mul(&numer, &three, &x1sq, &P256_P);       /* 3*x1^2 */
            bn_mod_sub(&numer, &numer, &three, &P256_P);      /* 3*x1^2 - 3 */

            BN256 two; bn_set_u32(&two, 2);
            BN256 denom;
            bn_mod_mul(&denom, &two, &a->y, &P256_P);         /* 2*y1 */
            bn_mod_inv(&tmp, &denom, &P256_P);                 /* 1/(2*y1) */
            bn_mod_mul(&lam, &numer, &tmp, &P256_P);           /* lambda */

            bn_mod_mul(&x3, &lam, &lam, &P256_P);             /* lam^2 */
            bn_mod_sub(&x3, &x3, &a->x, &P256_P);
            bn_mod_sub(&x3, &x3, &a->x, &P256_P);            /* x3 = lam^2-2x1 */

            bn_mod_sub(&tmp, &a->x, &x3, &P256_P);
            bn_mod_mul(&y3, &lam, &tmp, &P256_P);
            bn_mod_sub(&y3, &y3, &a->y, &P256_P);

            bn_copy(&r->x, &x3);
            bn_copy(&r->y, &y3);
            r->infinity = 0;
        } else {
            r->infinity = 1;   /* a + (-a) = point at infinity */
        }
        return;
    }

    /* General addition */
    BN256 lam, tmp, x3, y3;

    bn_mod_sub(&lam, &b->y, &a->y, &P256_P);                  /* y2-y1 */
    bn_mod_sub(&tmp, &b->x, &a->x, &P256_P);                  /* x2-x1 */
    bn_mod_inv(&x3, &tmp, &P256_P);                            /* 1/(x2-x1) */
    bn_mod_mul(&lam, &lam, &x3, &P256_P);                      /* lambda */

    bn_mod_mul(&x3, &lam, &lam, &P256_P);                     /* lam^2 */
    bn_mod_sub(&x3, &x3, &a->x, &P256_P);
    bn_mod_sub(&x3, &x3, &b->x, &P256_P);

    bn_mod_sub(&tmp, &a->x, &x3, &P256_P);
    bn_mod_mul(&y3, &lam, &tmp, &P256_P);
    bn_mod_sub(&y3, &y3, &a->y, &P256_P);

    bn_copy(&r->x, &x3);
    bn_copy(&r->y, &y3);
    r->infinity = 0;
}

/* -----------------------------------------------
 * Scalar multiplication: R = k * P
 * Method: double-and-add (MSB first)
 * 256 iterations, one bit at a time.
 * ----------------------------------------------- */
static void scalar_mul(ECPoint *r, const BN256 *k, const ECPoint *P) {
    ECPoint result, addend;
    result.infinity = 1;
    point_copy(&addend, P);

    for (int word = 0; word < 8; word++) {
        for (int bit = 0; bit < 32; bit++) {
            if ((k->d[word] >> bit) & 1)
                point_add(&result, &result, &addend);
            point_add(&addend, &addend, &addend);  /* double */
        }
    }
    point_copy(r, &result);
}

/* -----------------------------------------------
 * Key generation
 * ----------------------------------------------- */
int ecc_keygen(ECKeyPair *kp, const uint8_t seed[32]) {
    /* Private key = seed interpreted as big integer, reduced mod n */
    bn_from_bytes(&kp->priv, seed);

    /* Ensure 1 <= priv < n */
    while (bn_cmp(&kp->priv, &P256_N) >= 0)
        bn_sub(&kp->priv, &kp->priv, &P256_N);
    if (bn_is_zero(&kp->priv))
        kp->priv.d[0] = 1;   /* pathological case: just set to 1 */

    /* Public key Q = priv * G */
    ECPoint G;
    bn_copy(&G.x, &G_X);
    bn_copy(&G.y, &G_Y);
    G.infinity = 0;

    scalar_mul(&kp->pub, &kp->priv, &G);
    return 0;
}

/* -----------------------------------------------
 * ECDSA Sign
 *
 * Given: hash e (32 bytes), private key d, nonce k_nonce
 * Compute:
 *   R = k_nonce * G
 *   r = R.x mod n
 *   s = k_nonce^-1 * (e + d*r) mod n
 * ----------------------------------------------- */
int ecdsa_sign(ECDSASig *sig,
               const uint8_t hash[32],
               const BN256 *priv,
               const uint8_t nonce[32]) {
    BN256 k, e, tmp, kinv;
    ECPoint R;
    ECPoint G;
    bn_copy(&G.x, &G_X);
    bn_copy(&G.y, &G_Y);
    G.infinity = 0;

    bn_from_bytes(&k, nonce);
    /* k must be in [1, n-1] */
    while (bn_cmp(&k, &P256_N) >= 0)
        bn_sub(&k, &k, &P256_N);
    if (bn_is_zero(&k)) k.d[0] = 1;

    /* R = k * G */
    scalar_mul(&R, &k, &G);
    if (R.infinity) return -1;

    /* r = R.x mod n */
    bn_mod(&sig->r, &R.x, &P256_N);
    if (bn_is_zero(&sig->r)) return -2;

    /* s = k^-1 * (e + priv * r) mod n */
    bn_from_bytes(&e, hash);
    bn_mod(&e, &e, &P256_N);

    bn_mod_mul(&tmp, priv, &sig->r, &P256_N);   /* priv * r */
    bn_mod_add(&tmp, &tmp, &e, &P256_N);         /* e + priv*r */
    bn_mod_inv(&kinv, &k, &P256_N);              /* k^-1 */
    bn_mod_mul(&sig->s, &kinv, &tmp, &P256_N);   /* s */

    if (bn_is_zero(&sig->s)) return -3;
    return 0;
}

/* -----------------------------------------------
 * ECDSA Verify
 *
 * Given: hash e, signature (r,s), public key Q
 * Compute:
 *   w  = s^-1 mod n
 *   u1 = e*w mod n
 *   u2 = r*w mod n
 *   X  = u1*G + u2*Q
 *   Valid if X.x mod n == r
 * ----------------------------------------------- */
int ecdsa_verify(const ECDSASig *sig,
                 const uint8_t hash[32],
                 const ECPoint *pub) {
    BN256 e, w, u1, u2;
    ECPoint G, R1, R2, X;

    bn_copy(&G.x, &G_X);
    bn_copy(&G.y, &G_Y);
    G.infinity = 0;

    /* Basic range checks */
    if (bn_is_zero(&sig->r) || bn_cmp(&sig->r, &P256_N) >= 0) return -1;
    if (bn_is_zero(&sig->s) || bn_cmp(&sig->s, &P256_N) >= 0) return -1;

    bn_from_bytes(&e, hash);
    bn_mod(&e, &e, &P256_N);

    bn_mod_inv(&w, &sig->s, &P256_N);            /* w = s^-1 */
    bn_mod_mul(&u1, &e, &w, &P256_N);            /* u1 = e*w */
    bn_mod_mul(&u2, &sig->r, &w, &P256_N);       /* u2 = r*w */

    scalar_mul(&R1, &u1, &G);                    /* u1 * G */
    scalar_mul(&R2, &u2, pub);                   /* u2 * Q */
    point_add(&X, &R1, &R2);                     /* X = u1G + u2Q */

    if (X.infinity) return -1;

    BN256 xmod;
    bn_mod(&xmod, &X.x, &P256_N);
    return (bn_cmp(&xmod, &sig->r) == 0) ? 0 : -1;
}

/* -----------------------------------------------
 * Key serialization
 * ----------------------------------------------- */
void ecc_export_pubkey(const ECPoint *pub, uint8_t out[65]) {
    out[0] = 0x04;   /* uncompressed point marker */
    bn_to_bytes(&pub->x, out + 1);
    bn_to_bytes(&pub->y, out + 33);
}

int ecc_import_pubkey(ECPoint *pub, const uint8_t in[65]) {
    if (in[0] != 0x04) return -1;
    bn_from_bytes(&pub->x, in + 1);
    bn_from_bytes(&pub->y, in + 33);
    pub->infinity = 0;
    return 0;
}

void ecdsa_sig_to_bytes(const ECDSASig *sig, uint8_t out[64]) {
    bn_to_bytes(&sig->r, out);
    bn_to_bytes(&sig->s, out + 32);
}

int ecdsa_sig_from_bytes(ECDSASig *sig, const uint8_t in[64]) {
    bn_from_bytes(&sig->r, in);
    bn_from_bytes(&sig->s, in + 32);
    return 0;
}
