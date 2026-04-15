/*
 * uart_cmd.c — UART command interface
 * Uses uart_hw.h (bare-register) instead of HAL_UART_Transmit
 */

#include "uart_cmd.h"
#include "uart_hw.h"
#include "blockchain.h"
#include "crypto.h"
#include "sensor_sim.h"
#include "stm32f4xx.h"
#include <string.h>
#include <stdio.h>

static char rx_buf[256];
static int  rx_pos    = 0;
static int  erase_armed = 0;

/* -- Output helpers ----------------------------- */
static void out(const char *s)                        { uart_send_string(s); }
static void out_hex(const uint8_t *d, size_t l)       { uart_send_hex(d, l); }
static void prompt(void)                               { out("> "); }

/* -- Commands ----------------------------------- */
static void cmd_help(void) {
    out("\r\n=== Secure Logger Commands ===\r\n");
    out("  log           read sensor + add block\r\n");
    out("  verify        verify full chain\r\n");
    out("  dump          print all blocks\r\n");
    out("  sign <msg>    sign a message (wallet)\r\n");
    out("  pubkey        show device public key\r\n");
    out("  status        block count + validity\r\n");
    out("  erase         erase chain\r\n");
    out("==============================\r\n");
}

static void cmd_log(void) {
    SensorData d = sensor_read();
    int r = blockchain_add(d);
    if (r == 0) {
        char buf[128];
        snprintf(buf, sizeof(buf),
            "[Block #%lu] Temp:%lu.%02lu C  Hum:%lu.%02lu%%  P:%lu Pa\r\n",
            (unsigned long)(blockchain_count() - 1),
            (unsigned long)(d.temperature / 100),
            (unsigned long)(d.temperature % 100),
            (unsigned long)(d.humidity    / 100),
            (unsigned long)(d.humidity    % 100),
            (unsigned long) d.pressure);
        out(buf);
    } else {
        out("ERROR adding block\r\n");
    }
}

static void cmd_verify(void) {
    out("Verifying chain...\r\n");
    int r = blockchain_verify_all();
    if (r == 0) {
        out("Chain VALID - all blocks authentic\r\n");
    } else {
        char buf[64];
        snprintf(buf, sizeof(buf), "Chain INVALID - error code %d\r\n", r);
        out(buf);
    }
}

static void cmd_dump(void) {
    int n = blockchain_count();
    if (n == 0) { out("Chain empty. Use 'log' first.\r\n"); return; }
    char buf[160];
    for (int i = 0; i < n; i++) {
        Block b = blockchain_get(i);
        snprintf(buf, sizeof(buf),
            "\r\n[Block %lu] ts=%lu  Temp=%lu.%02lu C  Hum=%lu.%02lu%%\r\n",
            (unsigned long)b.index,
            (unsigned long)b.timestamp,
            (unsigned long)(b.data.temperature / 100),
            (unsigned long)(b.data.temperature % 100),
            (unsigned long)(b.data.humidity    / 100),
            (unsigned long)(b.data.humidity    % 100));
        out(buf);
        out("  Hash:     "); out_hex(b.hash,      32);
        out("  PrevHash: "); out_hex(b.prev_hash, 32);
        out("  Sig:      "); out_hex(b.signature, BLOCK_SIG_LEN);
    }
    out("\r\n");
}

static void cmd_sign(const char *msg) {
    if (!msg || strlen(msg) == 0) { out("Usage: sign <message>\r\n"); return; }

    uint8_t hash[32];
    crypto_hash((const uint8_t *)msg, strlen(msg), hash);

    uint8_t sig[64];
    if (crypto_sign(hash, sig) != 0) { out("ERROR: signing failed\r\n"); return; }

    out("Message:   "); out(msg); out("\r\n");
    out("Hash:      "); out_hex(hash, 32);
    out("Signature: "); out_hex(sig,  64);
    out("Status:    SIGNED OK\r\n");
}

static void cmd_pubkey(void) {
    uint8_t pub[65];
    crypto_get_pubkey(pub);
    out("PublicKey: ");
    out_hex(pub, 65);
}

static void cmd_status(void) {
    char buf[80];
    snprintf(buf, sizeof(buf), "Blocks: %d / %d\r\n", blockchain_count(), MAX_BLOCKS);
    out(buf);
    out(blockchain_verify_all() == 0 ? "Chain: VALID\r\n" : "Chain: INVALID\r\n");
}

static void cmd_erase(void) {
    if (!erase_armed) {
        out("WARNING: erases all blocks. Type 'erase' again to confirm.\r\n");
        erase_armed = 1;
    } else {
        blockchain_erase();
        erase_armed = 0;
        out("Chain erased.\r\n");
    }
}

/* -- Character processor (called from main poll loop) -- */
void uart_cmd_process_char(uint8_t c) {
    if (c == '\r' || c == '\n') {
        if (rx_pos == 0) { prompt(); return; }
        rx_buf[rx_pos] = '\0';
        rx_pos = 0;

        if      (strcmp(rx_buf, "help")   == 0) cmd_help();
        else if (strcmp(rx_buf, "log")    == 0) cmd_log();
        else if (strcmp(rx_buf, "verify") == 0) cmd_verify();
        else if (strcmp(rx_buf, "dump")   == 0) cmd_dump();
        else if (strcmp(rx_buf, "pubkey") == 0) cmd_pubkey();
        else if (strcmp(rx_buf, "status") == 0) cmd_status();
        else if (strcmp(rx_buf, "erase")  == 0) cmd_erase();
        else if (strncmp(rx_buf, "sign ", 5) == 0) cmd_sign(rx_buf + 5);
        else { out("Unknown command. Type 'help'\r\n"); }

        prompt();
    } else if (c == 127 || c == '\b') {
        if (rx_pos > 0) rx_pos--;
    } else {
        if (rx_pos < (int)sizeof(rx_buf) - 1)
            rx_buf[rx_pos++] = (char)c;
    }
}
