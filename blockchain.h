#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <stdint.h>
#include <stddef.h>
#include "sensor_sim.h"

#define BLOCK_SIG_LEN  32    /* HMAC-SHA256 = 32 bytes */
#define MAX_BLOCKS     64

typedef struct {
    uint32_t   index;
    uint32_t   timestamp;
    SensorData data;
    uint8_t    prev_hash[32];
    uint8_t    hash[32];
    uint8_t    signature[BLOCK_SIG_LEN];
    uint32_t   magic;
} Block;

void  blockchain_init(void);
int   blockchain_add(SensorData data);
int   blockchain_verify_all(void);
int   blockchain_count(void);
Block blockchain_get(int index);
void  blockchain_erase(void);

#endif