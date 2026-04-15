#ifndef BIGNUM_H
#define BIGNUM_H

/*
 * bignum.h — 256-bit big integer arithmetic for ECC P-256
 * From scratch, pure C, no dependencies.
 *
 * Representation: little-endian array of 8 × uint32_t
 * i.e. bn[0] is the LEAST significant 32-bit word.
 *
 * All operations are modular on the P-256 field prime p
 * or the curve order n, passed explicitly.
 */

#include <stdint.h>
#include <stddef.h>

/* 256-bit number as 8 × 32-bit limbs, little-endian */
typedef struct { uint32_t d[8]; } BN256;

/* -- Basic ops --------------------------------- */
void bn_zero   (BN256 *r);
void bn_one    (BN256 *r);
void bn_copy   (BN256 *r, const BN256 *a);
int  bn_is_zero(const BN256 *a);
int  bn_is_one (const BN256 *a);
int  bn_cmp    (const BN256 *a, const BN256 *b);  /* -1/0/1 */
void bn_set_u32(BN256 *r, uint32_t v);

/* -- Byte / hex I/O ---------------------------- */
void bn_from_bytes(BN256 *r, const uint8_t bytes[32]); /* big-endian */
void bn_to_bytes  (const BN256 *a, uint8_t bytes[32]); /* big-endian */

/* -- Arithmetic (no mod) ----------------------- */
uint32_t bn_add(BN256 *r, const BN256 *a, const BN256 *b); /* returns carry */
uint32_t bn_sub(BN256 *r, const BN256 *a, const BN256 *b); /* returns borrow */
void     bn_rshift1(BN256 *r);   /* r >>= 1 */
void     bn_lshift1(BN256 *r, uint32_t *carry); /* r <<= 1 */

/* -- Modular arithmetic ------------------------ */
void bn_mod_add(BN256 *r, const BN256 *a, const BN256 *b, const BN256 *m);
void bn_mod_sub(BN256 *r, const BN256 *a, const BN256 *b, const BN256 *m);
void bn_mod_mul(BN256 *r, const BN256 *a, const BN256 *b, const BN256 *m);
void bn_mod_inv(BN256 *r, const BN256 *a, const BN256 *m); /* r = a^-1 mod m */
void bn_mod    (BN256 *r, const BN256 *a, const BN256 *m); /* r = a mod m */

/* P-256 field prime and order (defined in bignum.c) */
extern const BN256 P256_P;   /* field prime */
extern const BN256 P256_N;   /* curve order */

#endif /* BIGNUM_H */
