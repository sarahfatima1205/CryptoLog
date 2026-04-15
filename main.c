#include "stm32f4xx.h"
#include "stm32f4xx_hal.h"   // ONLY for FLASH
#include "uart_hw.h"
#include "crypto.h"
#include "blockchain.h"
#include "uart_cmd.h"
#include "sensor_sim.h"
#include <stdio.h>
#include <string.h>

/* Simple delay */
void delay(volatile uint32_t t)
{
    while(t--);
}

int main(void)
{
    //HAL_Init();          // needed for FLASH timing
    uart_hw_init();      // YOUR WORKING UART

    uart_send_string("\r\n====================================\r\n");
    uart_send_string(" Secure Data Logger + Wallet\r\n");
    uart_send_string("====================================\r\n");

    uart_send_string("Initializing crypto...\r\n");

    if (crypto_init() != 0)
    {
        uart_send_string("Crypto FAILED\r\n");
        while(1);
    }

    uart_send_string("Crypto OK\r\n");

    /* Print public key */
    uint8_t pub[65];
    crypto_get_pubkey(pub);

    uart_send_string("PublicKey: ");
    uart_send_hex(pub, 65);

    /* Init blockchain */
    blockchain_init();

    char buf[64];
    sprintf(buf, "Blocks: %d\r\n", blockchain_count());
    uart_send_string(buf);

    uart_send_string("\r\nReady. Type 'help'\r\n> ");

    uint32_t counter = 0;

    while (1)
    {
        /* UART command handling */
        if (uart_recv_ready())
        {
            uint8_t c = uart_recv_char();
            uart_send_char(c);              // echo
            uart_cmd_process_char(c);       // process command
        }

        /* Auto logging (slow loop-based timing) */
        counter++;
        if (counter > 3000000)
        {
            counter = 0;

            SensorData d = sensor_read();
            blockchain_add(d);

            uart_send_string("\r\n[LOG] Block added\r\n> ");
        }
    }
}