#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

/*
 * blockchain.h — Tamper-evident hash chain stored in Flash
 *
 * Each block contains:
 *   - Sensor data
 *   - SHA-256 hash of (index + timestamp + data + prev_hash)
 *   - ECDSA signature of that hash
 *   - prev_hash linking to previous block
 *
 * Stored in Flash Sector 11 (0x080E0000, 128KB).
 * Max 64 blocks (each ~200 bytes).
 */

#include <stdint.h>
#include <stddef.h>
#include "sensor_sim.h"

#define BLOCK_SIG_LEN  64    /* R(32) + S(32) raw bytes */
#define MAX_BLOCKS     64

typedef struct {
    uint32_t   index;
    uint32_t   timestamp;
    SensorData data;
    uint8_t    prev_hash[32];
    uint8_t    hash[32];
    uint8_t    signature[BLOCK_SIG_LEN];
    uint32_t   magic;        /* 0xBLOCCAFE — sanity check */
} Block;

/* Init: scan flash and count existing blocks */
void  blockchain_init(void);

/* Add new block from sensor reading. Returns 0 on success. */
int   blockchain_add(SensorData data);

/* Verify entire chain. Returns 0 if valid, negative error code if not. */
int   blockchain_verify_all(void);

/* Accessors */
int   blockchain_count(void);
Block blockchain_get(int index);

/* Erase chain (erases Flash sector 11) */
void  blockchain_erase(void);

#endif /* BLOCKCHAIN_H */
