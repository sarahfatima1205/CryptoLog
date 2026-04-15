/*
 * sha256.c — SHA-256 from scratch, pure C, no dependencies
 * Implements FIPS PUB 180-4
 *
 * Every operation explained inline so you can defend this to any evaluator.
 */

#include "sha256.h"
#include <string.h>

/* ---------------------------------------------
 * SHA-256 constants
 * First 32 bits of fractional parts of cube roots
 * of first 64 primes. Fixed by the standard.
 * --------------------------------------------- */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* ---------------------------------------------
 * Bit operations
 * ROTR(x, n) = circular right rotate x by n bits
 * CH  = choose: if e then f else g
 * MAJ = majority: at least 2 of (a,b,c) are 1
 * --------------------------------------------- */
#define ROTR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(e,f,g)   (((e) & (f)) ^ (~(e) & (g)))
#define MAJ(a,b,c)  (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))

/* SHA-256 sigma functions — linear mixing */
#define SIG0(x)  (ROTR(x,2)  ^ ROTR(x,13) ^ ROTR(x,22))
#define SIG1(x)  (ROTR(x,6)  ^ ROTR(x,11) ^ ROTR(x,25))
#define sig0(x)  (ROTR(x,7)  ^ ROTR(x,18) ^ ((x) >> 3))
#define sig1(x)  (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

/* Big-endian read/write helpers */
#define BE32(b)  ( ((uint32_t)(b)[0] << 24) | \
                   ((uint32_t)(b)[1] << 16) | \
                   ((uint32_t)(b)[2] <<  8) | \
                   ((uint32_t)(b)[3]      ) )

static void be32_write(uint8_t *b, uint32_t x) {
    b[0] = (uint8_t)(x >> 24);
    b[1] = (uint8_t)(x >> 16);
    b[2] = (uint8_t)(x >>  8);
    b[3] = (uint8_t)(x      );
}
static void be64_write(uint8_t *b, uint64_t x) {
    be32_write(b,     (uint32_t)(x >> 32));
    be32_write(b + 4, (uint32_t)(x      ));
}

/* ---------------------------------------------
 * Core compression function
 * Processes one 64-byte (512-bit) block.
 * Updates the 8 working variables a..h in place
 * (via ctx->state).
 * --------------------------------------------- */
static void sha256_compress(SHA256_CTX *ctx, const uint8_t block[64]) {
    uint32_t W[64];   /* message schedule */
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t T1, T2;
    int i;

    /* Prepare message schedule W[0..63] */
    for (i = 0; i < 16; i++)
        W[i] = BE32(block + i * 4);
    for (i = 16; i < 64; i++)
        W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16];

    /* Load working variables from current hash state */
    a = ctx->state[0]; b = ctx->state[1];
    c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5];
    g = ctx->state[6]; h = ctx->state[7];

    /* 64 rounds */
    for (i = 0; i < 64; i++) {
        T1 = h + SIG1(e) + CH(e,f,g) + K[i] + W[i];
        T2 = SIG0(a) + MAJ(a,b,c);
        h = g; g = f; f = e;
        e = d + T1;
        d = c; c = b; b = a;
        a = T1 + T2;
    }

    /* Add compressed chunk to current hash state */
    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

/* ---------------------------------------------
 * Public API
 * --------------------------------------------- */

void sha256_init(SHA256_CTX *ctx) {
    /*
     * Initial hash values H0..H7
     * = first 32 bits of fractional parts of
     *   square roots of first 8 primes.
     * Fixed by FIPS 180-4.
     */
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->bit_count = 0;
    ctx->buf_len   = 0;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    ctx->bit_count += (uint64_t)len * 8;

    while (len > 0) {
        /* Fill buffer */
        uint32_t space = 64 - ctx->buf_len;
        uint32_t take  = (len < space) ? (uint32_t)len : space;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take;
        len  -= take;

        /* Compress when full */
        if (ctx->buf_len == 64) {
            sha256_compress(ctx, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[32]) {
    /* Padding: append 0x80, then zeros, then 64-bit big-endian bit length */
    uint8_t pad[64];
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;

    /* If less than 56 bytes in buffer: one padding block
     * Otherwise: two padding blocks                      */
    uint32_t pad_len = (ctx->buf_len < 56)
                       ? (56 - ctx->buf_len)
                       : (120 - ctx->buf_len);

    sha256_update(ctx, pad, pad_len);

    /* Append bit length as big-endian 64-bit */
    uint8_t len_bytes[8];
    be64_write(len_bytes, ctx->bit_count);
    sha256_update(ctx, len_bytes, 8);

    /* Extract final hash — big-endian 32-bit words */
    for (int i = 0; i < 8; i++)
        be32_write(hash + i * 4, ctx->state[i]);
}

/* One-shot convenience */
void sha256(const uint8_t *data, size_t len, uint8_t hash[32]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
}
