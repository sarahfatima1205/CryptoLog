# CryptoLog – Secure Data Logger + Hardware Wallet

## Features
- SHA-256 hashing
- ECDSA (P-256) signing
- Tamper-evident blockchain
- UART command interface
- Sensor data logging

## Commands
help  
log  
dump  
verify  
sign <message>  

## Hardware
- STM32F429I-DISC1
- UART (USART1, PA9/PA10)

## Description
Embedded system that logs sensor data securely and signs messages using a device-held private key.
