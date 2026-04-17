/*
 * uart_hw.c � Bare-register UART, no HAL
 * USART1 on PA9 (TX) / PA10 (RX)
 * 9600 baud, HSI 16MHz
 * BRR = 16000000 / 9600 = 1667
 */

#include "uart_hw.h"
#include "stm32f4xx.h"
#include <stdio.h>

void uart_hw_init(void) {
    /* GPIO A clock */
    RCC->AHB1ENR |= (1 << 0);
    /* USART1 clock (APB2 bit 4) */
    RCC->APB2ENR |= (1 << 4);


    GPIOA->MODER &= ~(3U << (9 * 2)); //clearing PA9 and then setting it as AF mode
    GPIOA->MODER |=  (2U << (9 * 2));

    GPIOA->AFR[1] &= ~(0xFU << 4); //AF7
    GPIOA->AFR[1] |=  (7U   << 4);


    GPIOA->MODER &= ~(3U << (10 * 2)); //clearing PA10 and then setting it as AF mode
    GPIOA->MODER |=  (2U << (10 * 2));

    GPIOA->AFR[1] &= ~(0xFU << 8); 
    GPIOA->AFR[1] |=  (7U   << 8); //AF7

    /* Baud rate */
    USART1->BRR = 1667;

   //UE,TE,RE
    USART1->CR1 = (1 << 13) |   
                  (1 <<  3) |   
                  (1 <<  2);    
}

void uart_send_char(char c) {
    /* Wait until TXE (transmit data register empty) */
    while (!(USART1->SR & (1 << 7)));
    USART1->DR = (uint8_t)c;
}

void uart_send_string(const char *s) {
    while (*s) uart_send_char(*s++);
}

void uart_send_bytes(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++)
        uart_send_char((char)data[i]); //uart_send_char((uint8_t)data[i]);
}

void uart_send_hex(const uint8_t *data, size_t len) { //BINARY DATA TO HEX STRING
    const char hex_chars[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; i++) {
        uart_send_char(hex_chars[(data[i] >> 4) & 0xF]);
        uart_send_char(hex_chars[ data[i]       & 0xF]);
    }
    uart_send_string("\r\n");
}

uint8_t uart_recv_char(void) {
    /* Wait until RXNE (read data register not empty) */
    while (!(USART1->SR & (1 << 5)));
    return (uint8_t)(USART1->DR & 0xFF);
}

int uart_recv_ready(void) {
    return (USART1->SR & (1 << 5)) ? 1 : 0;
}
