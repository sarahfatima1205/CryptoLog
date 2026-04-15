#ifndef UART_HW_H
#define UART_HW_H

/*
 * uart_hw.c — Bare-register UART driver
 * USART1, PA9 (TX), PA10 (RX), 9600 baud, HSI 16MHz
 * No HAL. Matches the approach confirmed working on this board.
 */

#include <stdint.h>
#include <stddef.h>

void    uart_hw_init(void);
void    uart_send_char(char c);
void    uart_send_string(const char *s);
void    uart_send_bytes(const uint8_t *data, size_t len);
void    uart_send_hex(const uint8_t *data, size_t len);
uint8_t uart_recv_char(void);          /* blocking */
int     uart_recv_ready(void);         /* 1 if byte waiting */

#endif
