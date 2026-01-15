#!/usr/bin/env python3
"""
Fake external signer for tests.

Reads base64(message) from stdin and writes base64(signature) to stdout.

Seed is taken from FAKE_SIGNER_SEED_HEX (32-byte hex). If not provided,
a deterministic default is used.
"""
import os, sys, base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

DEFAULT_SEED_HEX = "1f"*32

def main():
    seed_hex = (os.getenv("FAKE_SIGNER_SEED_HEX") or DEFAULT_SEED_HEX).strip()
    try:
        seed = bytes.fromhex(seed_hex)
    except Exception:
        print("invalid seed hex", file=sys.stderr)
        return 2
    if len(seed) != 32:
        print("seed must be 32 bytes", file=sys.stderr)
        return 2

    msg_b64 = sys.stdin.read().strip()
    try:
        msg = base64.b64decode(msg_b64.encode("ascii"), validate=True)
    except Exception:
        print("invalid base64 message", file=sys.stderr)
        return 2

    sk = Ed25519PrivateKey.from_private_bytes(seed)
    sig = sk.sign(msg)
    sys.stdout.write(base64.b64encode(sig).decode("ascii"))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
