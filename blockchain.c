/*
 * blockchain.c — Hash chain, Flash sector 11
 * Uses bare-register Flash programming — no HAL needed.
 *
 * STM32F429 Flash sector 11: 0x080E0000, 128KB
 */

#include "blockchain.h"
#include "crypto.h"
#include "stm32f4xx.h"
#include <string.h>

#define FLASH_CHAIN_BASE  0x080E0000UL
#define BLOCK_MAGIC       0x0B10CCA0UL

static Block * const flash_chain = (Block *)FLASH_CHAIN_BASE;
static int block_count = 0;

/* -- Bare-register Flash driver ----------------- */

static void flash_wait_busy(void) {
    while (FLASH->SR & FLASH_SR_BSY);
}

static void flash_unlock(void) {
    if (FLASH->CR & FLASH_CR_LOCK) {
        FLASH->KEYR = 0x45670123UL;
        FLASH->KEYR = 0xCDEF89ABUL;
    }
}

static void flash_lock(void) {
    FLASH->CR |= FLASH_CR_LOCK;
}

static void flash_erase_sector11(void) {
    flash_wait_busy();
    /* Sector erase: SNB=11, SER=1, STRT=1, PSIZE=2 (32-bit) */
    FLASH->CR &= ~(FLASH_CR_SNB | FLASH_CR_PSIZE);
    FLASH->CR |= (11 << FLASH_CR_SNB_Pos)
               | FLASH_CR_SER
               | (2  << FLASH_CR_PSIZE_Pos);
    FLASH->CR |= FLASH_CR_STRT;
    flash_wait_busy();
    FLASH->CR &= ~FLASH_CR_SER;
}

static void flash_write_word(uint32_t addr, uint32_t data) {
    flash_wait_busy();
    FLASH->CR &= ~FLASH_CR_PSIZE;
    FLASH->CR |= (2 << FLASH_CR_PSIZE_Pos);   /* 32-bit */
    FLASH->CR |= FLASH_CR_PG;
    *(__IO uint32_t *)addr = data;
    flash_wait_busy();
    FLASH->CR &= ~FLASH_CR_PG;
}

static void flash_write_block(int index, const Block *b) {
    uint32_t addr = FLASH_CHAIN_BASE + (uint32_t)index * sizeof(Block);
    const uint8_t *src = (const uint8_t *)b;
    flash_unlock();
    for (size_t i = 0; i < sizeof(Block); i += 4) {
        uint32_t word;
        memcpy(&word, src + i, 4);
        flash_write_word(addr + i, word);
    }
    flash_lock();
}

static void flash_erase_chain(void) {
    flash_unlock();
    flash_erase_sector11();
    flash_lock();
}

/* -- Serialise block for hashing --------------- */
static size_t block_to_hashable(const Block *b, uint8_t *buf) {
    size_t pos = 0;
    memcpy(buf + pos, &b->index,             4); pos += 4;
    memcpy(buf + pos, &b->timestamp,         4); pos += 4;
    memcpy(buf + pos, &b->data.temperature,  4); pos += 4;
    memcpy(buf + pos, &b->data.pressure,     4); pos += 4;
    memcpy(buf + pos, &b->data.humidity,     4); pos += 4;
    memcpy(buf + pos, &b->data.timestamp,    4); pos += 4;
    memcpy(buf + pos,  b->prev_hash,        32); pos += 32;
    return pos;   /* 56 bytes */
}

/* -- Public API --------------------------------- */

void blockchain_init(void) {
    block_count = 0;
    for (int i = 0; i < MAX_BLOCKS; i++) {
        if (flash_chain[i].magic == BLOCK_MAGIC &&
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
    b.magic     = BLOCK_MAGIC;

    if (block_count == 0)
        memset(b.prev_hash, 0, 32);
    else
        memcpy(b.prev_hash, flash_chain[block_count - 1].hash, 32);

    uint8_t raw[64];
    size_t  raw_len = block_to_hashable(&b, raw);
    crypto_hash(raw, raw_len, b.hash);

    if (crypto_sign(b.hash, b.signature) != 0) return -2;

    flash_write_block(block_count, &b);
    block_count++;
    return 0;
}

int blockchain_verify_all(void) {
    uint8_t expected_prev[32];
    memset(expected_prev, 0, 32);

    for (int i = 0; i < block_count; i++) {
        Block b = flash_chain[i];

        if (b.magic != BLOCK_MAGIC)               return -(i*10 + 1);
        if (b.index != (uint32_t)i)               return -(i*10 + 2);
        if (memcmp(b.prev_hash, expected_prev,32) != 0) return -(i*10 + 3);

        uint8_t raw[64]; size_t raw_len = block_to_hashable(&b, raw);
        uint8_t computed[32];
        crypto_hash(raw, raw_len, computed);
        if (memcmp(computed, b.hash, 32) != 0)    return -(i*10 + 4);
        if (crypto_verify(b.hash, b.signature) != 0) return -(i*10 + 5);

        memcpy(expected_prev, b.hash, 32);
    }
    return 0;
}

int   blockchain_count(void)    { return block_count; }
Block blockchain_get(int i)     { return flash_chain[i]; }
void  blockchain_erase(void)    { flash_erase_chain(); block_count = 0; }