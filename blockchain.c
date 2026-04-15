/*
 * blockchain.c — Hash chain with Flash storage
 *
 * Flash map for STM32F429ZI (2MB):
 *   Sectors 0-7:   16KB each  (code)
 *   Sector  8:     64KB
 *   Sectors 9-11:  128KB each
 *   We use Sector 11: 0x080E0000 — safely above code region
 */

#include "blockchain.h"
#include "crypto.h"
#include "stm32f4xx_hal.h"
#include <string.h>

#define FLASH_CHAIN_BASE   0x080E0000UL
#define FLASH_CHAIN_SECTOR FLASH_SECTOR_11
#define BLOCK_MAGIC        0xBL0CCA  /* 0x0B10CCA — hex for BLOCCA */

/* Cast flash base to array of Block for easy reading */
static Block * const flash_chain = (Block *)FLASH_CHAIN_BASE;
static int block_count = 0;

/* -----------------------------------------------
 * Flash helpers
 * ----------------------------------------------- */
static void flash_write_block(int index, const Block *b) {
    HAL_FLASH_Unlock();
    uint32_t addr = FLASH_CHAIN_BASE + (uint32_t)index * sizeof(Block);
    const uint8_t *src = (const uint8_t *)b;
    for (size_t i = 0; i < sizeof(Block); i += 4) {
        uint32_t word;
        memcpy(&word, src + i, 4);
        HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, addr + i, word);
    }
    HAL_FLASH_Lock();
}

static void flash_erase_chain(void) {
    HAL_FLASH_Unlock();
    FLASH_EraseInitTypeDef erase = {
        .TypeErase    = FLASH_TYPEERASE_SECTORS,
        .Sector       = FLASH_CHAIN_SECTOR,
        .NbSectors    = 1,
        .VoltageRange = FLASH_VOLTAGE_RANGE_3
    };
    uint32_t err;
    HAL_FLASHEx_Erase(&erase, &err);
    HAL_FLASH_Lock();
}

/* -----------------------------------------------
 * Serialise block fields into byte buffer for hashing
 * MUST match exactly what verifier.py computes.
 * ----------------------------------------------- */
static size_t block_to_hashable(const Block *b, uint8_t *buf) {
    size_t pos = 0;
    memcpy(buf + pos, &b->index,    4); pos += 4;
    memcpy(buf + pos, &b->timestamp,4); pos += 4;
    /* sensor data fields in fixed order */
    memcpy(buf + pos, &b->data.temperature, 4); pos += 4;
    memcpy(buf + pos, &b->data.pressure,    4); pos += 4;
    memcpy(buf + pos, &b->data.humidity,    4); pos += 4;
    memcpy(buf + pos, &b->data.timestamp,   4); pos += 4;
    memcpy(buf + pos, b->prev_hash, 32); pos += 32;
    return pos;   /* should be 56 bytes */
}

/* -----------------------------------------------
 * Public API
 * ----------------------------------------------- */

void blockchain_init(void) {
    block_count = 0;
    for (int i = 0; i < MAX_BLOCKS; i++) {
        if (flash_chain[i].magic == 0x0B10CCA &&
            flash_chain[i].index == (uint32_t)i) {
            block_count++;
        } else {
            break;
        }
    }
}

int blockchain_add(SensorData data) {
    if (block_count >= MAX_BLOCKS) return -1;

    Block b;
    memset(&b, 0, sizeof(b));

    b.index     = (uint32_t)block_count;
    b.timestamp = data.timestamp;
    b.data      = data;
    b.magic     = 0x0B10CCA;

    /* Previous hash: zero for genesis, else last block's hash */
    if (block_count == 0) {
        memset(b.prev_hash, 0, 32);
    } else {
        memcpy(b.prev_hash, flash_chain[block_count - 1].hash, 32);
    }

    /* Compute hash over (index, timestamp, sensor fields, prev_hash) */
    uint8_t raw[64];
    size_t raw_len = block_to_hashable(&b, raw);
    crypto_hash(raw, raw_len, b.hash);

    /* Sign the hash */
    if (crypto_sign(b.hash, b.signature) != 0) return -2;

    /* Write to Flash */
    flash_write_block(block_count, &b);
    block_count++;
    return 0;
}

int blockchain_verify_all(void) {
    uint8_t expected_prev[32];
    memset(expected_prev, 0, 32);

    for (int i = 0; i < block_count; i++) {
        Block b = flash_chain[i];

        /* Magic + index sanity */
        if (b.magic != 0x0B10CCA)          return -(i * 10 + 1);
        if (b.index != (uint32_t)i)        return -(i * 10 + 2);

        /* Chain linkage */
        if (memcmp(b.prev_hash, expected_prev, 32) != 0)
                                            return -(i * 10 + 3);

        /* Recompute hash */
        uint8_t raw[64];
        size_t  raw_len = block_to_hashable(&b, raw);
        uint8_t computed[32];
        crypto_hash(raw, raw_len, computed);
        if (memcmp(computed, b.hash, 32) != 0)
                                            return -(i * 10 + 4);

        /* Verify signature */
        if (crypto_verify(b.hash, b.signature) != 0)
                                            return -(i * 10 + 5);

        memcpy(expected_prev, b.hash, 32);
    }
    return 0;
}

int   blockchain_count(void)        { return block_count; }
Block blockchain_get(int i)         { return flash_chain[i]; }

void  blockchain_erase(void) {
    flash_erase_chain();
    block_count = 0;
}
