#!/usr/bin/env python3
"""
verifier.py — Full chain + signature verifier for SecureLogger
Implements the same SHA-256 hash and ECDSA P-256 verify in Python.

Requirements:
    pip install pyserial cryptography

Usage:
    python verifier.py           # live verify from device
    python verifier.py --file dump.txt   # verify from saved dump
"""

import sys
import re
import time
import argparse
import hashlib
import struct

# ── Cryptography imports (stdlib + cryptography package) ──
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1, EllipticCurvePublicNumbers, ECDSA
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature
)

try:
    import serial
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False

PORT = "COM3"         # ← Change to your port
BAUD = 115200         # Linux: /dev/ttyACM0 or /dev/ttyUSB0

# ═══════════════════════════════════════════════════════════
# Hash computation — MUST match block_to_hashable() in C
# Fields: index(4) + timestamp(4) + temp(4) + press(4) + hum(4) + ts_data(4) + prev_hash(32)
# Total: 56 bytes, little-endian uint32 for each field
# ═══════════════════════════════════════════════════════════
def compute_block_hash(index, timestamp, temp, pressure, humidity,
                        sensor_ts, prev_hash_bytes):
    raw = struct.pack('<IIIIII', index, timestamp, temp, pressure, humidity, sensor_ts)
    raw += prev_hash_bytes
    assert len(raw) == 56, f"Expected 56 bytes, got {len(raw)}"
    return hashlib.sha256(raw).digest()


# ═══════════════════════════════════════════════════════════
# ECDSA P-256 verification using raw R||S (64 bytes)
# ═══════════════════════════════════════════════════════════
def verify_ecdsa_p256(pub_key_bytes_65, message_hash_32, sig_bytes_64):
    """
    pub_key_bytes_65: uncompressed point 0x04 | X(32) | Y(32)
    message_hash_32:  SHA-256 hash bytes
    sig_bytes_64:     raw R(32) || S(32)
    Returns True if valid.
    """
    if pub_key_bytes_65[0] != 0x04:
        raise ValueError("Not an uncompressed public key")

    x = int.from_bytes(pub_key_bytes_65[1:33],  'big')
    y = int.from_bytes(pub_key_bytes_65[33:65], 'big')
    r = int.from_bytes(sig_bytes_64[:32],  'big')
    s = int.from_bytes(sig_bytes_64[32:],  'big')

    pub_numbers = EllipticCurvePublicNumbers(x, y, SECP256R1())
    pub_key = pub_numbers.public_key(default_backend())

    # Convert raw R,S to DER for cryptography library
    der_sig = encode_dss_signature(r, s)

    try:
        pub_key.verify(der_sig, message_hash_32, ECDSA(hashes.Prehashed()))
        return True
    except InvalidSignature:
        return False


# ═══════════════════════════════════════════════════════════
# UART helpers
# ═══════════════════════════════════════════════════════════
def serial_send(ser, cmd, wait=1.0):
    ser.write((cmd + "\r").encode())
    time.sleep(wait)
    out = ser.read(ser.in_waiting)
    return out.decode(errors='replace')


def get_pubkey_from_device(ser):
    resp = serial_send(ser, "pubkey", wait=0.5)
    m = re.search(r"PublicKey:\s*([0-9A-Fa-f]{130})", resp)
    if not m:
        raise ValueError(f"Could not parse public key from: {repr(resp)}")
    return bytes.fromhex(m.group(1))


def get_dump_from_device(ser):
    return serial_send(ser, "dump", wait=3.0)


# ═══════════════════════════════════════════════════════════
# Parse dump output
# ═══════════════════════════════════════════════════════════
def parse_dump(text):
    """
    Parse the UART dump output into a list of block dicts.
    Each dict has: index, timestamp, temp, pressure, humidity,
                   sensor_ts, hash, prev_hash, sig
    """
    blocks = []
    current = None

    for line in text.splitlines():
        line = line.strip()

        # New block header: [Block N] ts=X  Temp=Y°C  Hum=Z%
        m = re.match(r'\[Block (\d+)\]\s+ts=(\d+)\s+Temp=(\d+)\.(\d+).*?Hum=(\d+)\.(\d+)', line)
        if m:
            if current:
                blocks.append(current)
            current = {
                'index':     int(m.group(1)),
                'timestamp': int(m.group(2)),
                'temp':      int(m.group(3)) * 100 + int(m.group(4)),
                'humidity':  int(m.group(5)) * 100 + int(m.group(6)),
                'pressure':  None,   # not in header line, use 0 or parse separately
                'sensor_ts': int(m.group(2)),  # same as block timestamp in our sim
            }
            continue

        if current is None:
            continue

        h = re.match(r'Hash:\s+([0-9A-Fa-f]{64})', line)
        if h:
            current['hash'] = bytes.fromhex(h.group(1))
            continue

        p = re.match(r'PrevHash:\s+([0-9A-Fa-f]{64})', line)
        if p:
            current['prev_hash'] = bytes.fromhex(p.group(1))
            continue

        s = re.match(r'Sig:\s+([0-9A-Fa-f]{128})', line)
        if s:
            current['sig'] = bytes.fromhex(s.group(1))
            continue

    if current:
        blocks.append(current)

    return blocks


# ═══════════════════════════════════════════════════════════
# Main verification logic
# ═══════════════════════════════════════════════════════════
def verify_chain(blocks, pub_key_bytes):
    if not blocks:
        print("No blocks to verify.")
        return False

    print(f"\n{'─'*52}")
    print(f"  Verifying {len(blocks)} block(s) | P-256 ECDSA + SHA-256")
    print(f"{'─'*52}")

    prev_hash = b'\x00' * 32
    all_ok = True

    for b in blocks:
        idx = b['index']
        errors = []

        # 1. Chain linkage check
        if b.get('prev_hash') != prev_hash:
            errors.append("CHAIN BREAK: prev_hash mismatch")

        # 2. Recompute hash and compare
        if b.get('pressure') is None:
            b['pressure'] = 101000  # default — improve by parsing dump
        computed_hash = compute_block_hash(
            b['index'], b['timestamp'],
            b['temp'], b['pressure'], b['humidity'],
            b['sensor_ts'], prev_hash
        )
        if computed_hash != b.get('hash'):
            errors.append("HASH MISMATCH: data may be tampered")

        # 3. Signature verification
        sig_ok = False
        if b.get('sig') and b.get('hash'):
            try:
                sig_ok = verify_ecdsa_p256(pub_key_bytes, b['hash'], b['sig'])
            except Exception as e:
                errors.append(f"SIG ERROR: {e}")
        else:
            errors.append("Missing sig or hash")

        if not sig_ok and not any('SIG' in e for e in errors):
            errors.append("SIG INVALID")

        ok = len(errors) == 0 and sig_ok
        if not ok:
            all_ok = False

        # Print result
        sig_sym  = "✓ SIG" if sig_ok else "✗ SIG"
        hash_sym = "✓ HASH" if computed_hash == b.get('hash') else "✗ HASH"
        chain_sym= "✓ CHAIN" if b.get('prev_hash') == prev_hash else "✗ CHAIN"
        status   = "✓ OK" if ok else "✗ FAIL"

        print(f"  Block {idx:3d}: {status:8s} | {sig_sym}  {hash_sym}  {chain_sym}")
        for err in errors:
            print(f"             ↳ {err}")

        prev_hash = b.get('hash', prev_hash)

    print(f"{'─'*52}")
    if all_ok:
        print("  ✓ CHAIN VALID — all blocks authentic and unmodified")
    else:
        print("  ✗ CHAIN INVALID — tampering or corruption detected")
    print(f"{'─'*52}\n")
    return all_ok


# ═══════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description='Secure Logger Chain Verifier')
    parser.add_argument('--port',  default=PORT,  help='Serial port (e.g. COM3, /dev/ttyACM0)')
    parser.add_argument('--baud',  default=BAUD,  type=int)
    parser.add_argument('--file',  default=None,  help='Verify from saved dump file instead of device')
    parser.add_argument('--pubkey', default=None, help='Hex public key (65 bytes, for --file mode)')
    args = parser.parse_args()

    if args.file:
        # Offline mode: read dump from file
        if not args.pubkey:
            print("ERROR: --pubkey required in --file mode")
            print("  Get it from device: pubkey command")
            sys.exit(1)
        pub_bytes = bytes.fromhex(args.pubkey)
        with open(args.file) as f:
            dump_text = f.read()
        blocks = parse_dump(dump_text)
        verify_chain(blocks, pub_bytes)
    else:
        # Live mode: connect to device
        if not SERIAL_AVAILABLE:
            print("ERROR: pyserial not installed. Run: pip install pyserial")
            sys.exit(1)
        print(f"Connecting to {args.port} at {args.baud} baud...")
        with serial.Serial(args.port, args.baud, timeout=2) as ser:
            time.sleep(1)
            ser.read(ser.in_waiting)  # flush

            print("Reading public key from device...")
            pub_bytes = get_pubkey_from_device(ser)
            print(f"  PublicKey: {pub_bytes.hex()[:20]}...{pub_bytes.hex()[-8:]}")

            print("Reading chain dump from device...")
            dump = get_dump_from_device(ser)
            blocks = parse_dump(dump)
            print(f"  Found {len(blocks)} block(s) in dump")

            verify_chain(blocks, pub_bytes)


if __name__ == "__main__":
    main()
