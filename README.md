# CryptoLog – Secure Data Logger + Hardware Wallet

CryptoLog is an embedded system project that implements a secure data logger combined with a hardware wallet functionality on the STM32F429I-DISC1 microcontroller. It uses cryptographic primitives like SHA-256 and ECDSA (P-256) to ensure tamper-evident logging of sensor data and secure message signing.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Hardware Requirements](#hardware-requirements)
- [Software Requirements](#software-requirements)
- [Installation and Setup](#installation-and-setup)
- [Usage](#usage)
- [Building the Project](#building-the-project)
- [Commands](#commands)
- [Python Clients](#python-clients)
- [Security Considerations](#security-considerations)
- [License](#license)

## Features

- **SHA-256 Hashing**: Implemented from scratch for blockchain integrity
- **ECDSA P-256 Signing**: Elliptic Curve Digital Signature Algorithm for secure message signing
- **Tamper-Evident Blockchain**: Immutable chain of sensor data blocks with cryptographic links
- **UART Command Interface**: Interactive terminal for device control
- **Sensor Data Logging**: Simulated sensor readings (temperature, pressure, humidity) with timestamps
- **Auto-Logging**: Automatic data logging every 120 seconds
- **Hardware Wallet**: Secure private key storage and message signing
- **Python Verification Tools**: Cross-platform verification of blockchain integrity and signatures

## Architecture

The system consists of several modules:

- **main.c**: Main application loop, initialization, and auto-logging timer
- **crypto.c/h**: Cryptographic functions (SHA-256, ECDSA key generation, signing, verification)
- **blockchain.c/h**: Blockchain data structure and operations (add blocks, verify chain)
- **bignum.c/h**: Big integer arithmetic for elliptic curve operations
- **ecc.c/h**: Elliptic Curve Cryptography implementation (P-256 curve)
- **sha256.c/h**: SHA-256 hash function implementation
- **sensor_sim.c/h**: Simulated sensor data generation
- **uart_hw.c/h**: Low-level UART hardware interface
- **uart_cmd.c/h**: Command parsing and execution
- **verifier.py**: Python script for blockchain and signature verification
- **wallet_client.py**: Python client for interactive device control and demonstrations

## Hardware Requirements

- STM32F429I-DISC1 Discovery Board
- USB-to-UART adapter (for serial communication)
- Computer with serial terminal (e.g., PuTTY, minicom) or Python scripts

## Software Requirements

### For Embedded Development:
- Keil µVision IDE (version 5 or later)
- STM32F4xx Device Support Package
- ARM Compiler 6

### For Python Clients:
- Python 3.6+
- pyserial library: `pip install pyserial`
- cryptography library: `pip install cryptography`

## Installation and Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/sarahfatima1205/CryptoLog.git
   cd CryptoLog_3
   ```

2. **Open in Keil µVision**:
   - Launch Keil µVision
   - Open the project file: `cryptolog_3.uvprojx`

3. **Configure Target**:
   - Select Target: `Target 1`
   - Ensure STM32F429ZITx is selected as the device

4. **Build and Flash**:
   - Build the project (F7)
   - Flash to the board (F8)

5. **Connect Serial Interface**:
   - Connect STM32F429I-DISC1 via USB
   - Note the COM port (e.g., COM3 on Windows)
   - Set baud rate to 115200

## Usage

### Device Operation

1. Power on the STM32F429I-DISC1 board
2. Connect via serial terminal at 115200 baud
3. The device will initialize and display the public key
4. Use commands to interact with the device (see [Commands](#commands))

### LED Indicators

- **Green LED (PG13)**: Toggles on each auto-log event
- **Red LED (PG14)**: Error indicator (currently unused)

## Building the Project

1. Open `cryptolog_3.uvprojx` in Keil µVision
2. Select the appropriate target configuration
3. Build the project:
   - Project → Build target (F7)
4. Flash to device:
   - Flash → Download (F8)

The project uses bare-metal register access without HAL libraries for minimal footprint.

## Commands

The device accepts the following UART commands:

- `help`: Display available commands
- `log`: Manually log a sensor data block
- `dump`: Dump all blockchain data to serial
- `verify`: Verify blockchain integrity
- `sign <message>`: Sign a message with the device's private key
- `pubkey`: Display the device's public key
- `status`: Show current blockchain status
- `erase`: Clear all blockchain data (use with caution)

Commands are entered via UART terminal, followed by Enter.

## Python Clients

### Verifier (`verifier.py`)

Verifies blockchain integrity and signatures:

```bash
# Live verification from device
python verifier.py

# Verify from saved dump file
python verifier.py --file dump.txt
```

### Wallet Client (`wallet_client.py`)

Interactive terminal client with demonstration modes:

```bash
# Interactive mode
python wallet_client.py

# Tamper demonstration
python wallet_client.py --tamper

# Challenge-response demo
python wallet_client.py --challenge
```

**Note**: Update the `PORT` variable in Python scripts to match your system's serial port.

## Security Considerations

- **Private Key Storage**: The private key is generated on-device and never leaves the hardware
- **Tamper Detection**: Blockchain uses cryptographic hashing to detect any data modification
- **Secure Boot**: Crypto initialization failure halts the device
- **No External Dependencies**: All crypto implemented from scratch for auditability

**Warning**: This is an educational project. Do not use for production cryptographic applications without thorough security review.

## License

This project is released under the MIT License. See LICENSE file for details.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Acknowledgments

- Based on educational implementations of cryptographic algorithms
- Inspired by hardware security modules and blockchain concepts
- Developed as part of cryptographic systems coursework
