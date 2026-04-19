/*
 * main.c — Secure Data Logger + Wallet
 * STM32F429I-DISC1, HSI 16MHz, USART1 PA9/PA10, 9600 baud
 */

#include "stm32f4xx.h"
#include "uart_hw.h"
#include "crypto.h"
#include "blockchain.h"
#include "uart_cmd.h"
#include "sensor_sim.h"
#include <string.h>
#include <stdio.h>

/* No HAL at all — bare register only */

<<<<<<< HEAD
static void soft_delay(volatile uint32_t n) { while (n--); }
=======
int main(void)
{
    //HAL_Init();          // needed for FLASH timing
    uart_hw_init();      // WORKING UART
>>>>>>> 56b3653d71a9506bf9a15f49ac228248589fe1e6

int main(void) {
    uart_hw_init();

    uart_send_string("\r\n");
    uart_send_string("=====================================\r\n");
    uart_send_string("  Secure Data Logger + Wallet\r\n");
    uart_send_string("  SHA-256 + ECDSA P-256 from scratch\r\n");
    uart_send_string("=====================================\r\n");
    uart_send_string("Initializing crypto...\r\n");

<<<<<<< HEAD
    if (crypto_init() != 0) {
        uart_send_string("FATAL: crypto_init failed.\r\n");
        while (1);
=======
    if (crypto_init() != 0)
    {
        uart_send_string("Crypto FAILED\r\n"); //system halt if crypto fails
        while(1);
>>>>>>> 56b3653d71a9506bf9a15f49ac228248589fe1e6
    }

    uart_send_string("Crypto OK\r\n");

    uint8_t pub[65];
    crypto_get_pubkey(pub);
    uart_send_string("PublicKey: ");
    uart_send_hex(pub, 65);

    blockchain_init();
    char buf[48];
    snprintf(buf, sizeof(buf), "Blocks: %d\r\n", blockchain_count());
    uart_send_string(buf);

    /* LED init PG13=green PG14=red */
    RCC->AHB1ENR |= (1 << 6);
    GPIOG->MODER &= ~((3 << (13*2)) | (3 << (14*2)));
    GPIOG->MODER |=  ((1 << (13*2)) | (1 << (14*2)));

    uart_send_string("\r\nReady. Type 'help'\r\n> ");

    /*
     * Auto-log counter.
     * At 16MHz, each empty loop iteration ~= a few cycles.
     * 16000000 iterations ~ 1 second (rough).
     * We want auto-log every ~120 seconds = 1,920,000,000 iterations.
     * That overflows uint32. So we use a two-level counter:
     *   inner: counts to 160000  (~10ms per tick at 16MHz)
     *   outer: counts to 12000   (12000 * 10ms = 120s)
     * Reset outer counter on any keypress so typing is never interrupted.
     */
    uint32_t inner = 0;
    uint32_t outer = 0;
    const uint32_t INNER_MAX = 160000UL;
    const uint32_t OUTER_MAX = 12000UL;   /* ~120 seconds */

    while (1) {
        /* -- Check UART byte -- */
        if (uart_recv_ready()) {
            uint8_t c = uart_recv_char();
            uart_send_char((char)c);
            uart_cmd_process_char(c);
            outer = 0;    /* reset auto-log timer on any keypress */
            inner = 0;
        }

        /* -- Auto-log tick -- */
        inner++;
        if (inner >= INNER_MAX) {
            inner = 0;
            outer++;
            if (outer >= OUTER_MAX) {
                outer = 0;
                uart_send_string("\r\n[AUTO] logging block...\r\n> ");
                SensorData d = sensor_read();
                blockchain_add(d);
                GPIOG->ODR ^= (1 << 13);
            }
        }
    }
}