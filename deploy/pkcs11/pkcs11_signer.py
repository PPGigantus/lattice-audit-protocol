#!/usr/bin/env python3
"""PKCS#11 external signer wrapper (reference).

Reads message bytes from stdin and prints a base64 signature to stdout.

This script shells out to `pkcs11-tool` for portability. Mechanism names vary by module.
If your module doesn't support Ed25519/EdDSA via pkcs11-tool, replace the signing command
with your vendor's SDK/CLI while keeping the same stdin->stdout contract.

Usage:
  pkcs11_signer.py --module /path/to/module.so --slot 0 --key-id 01 [--pin-env PKCS11_PIN]
"""

import argparse
import base64
import os
import subprocess
import sys
import tempfile

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--module", required=True, help="Path to PKCS#11 module .so")
    ap.add_argument("--slot", required=True, help="Slot number (string, passed to pkcs11-tool)")
    ap.add_argument("--key-id", required=True, help="Key ID/label, passed to pkcs11-tool --id")
    ap.add_argument("--pin-env", default="PKCS11_PIN", help="Env var containing user PIN (optional)")
    ap.add_argument("--mechanism", default="EDDSA", help="Signing mechanism (module-specific)")
    args = ap.parse_args()

    msg = sys.stdin.buffer.read()
    if not msg:
        print("ERROR: no input to sign", file=sys.stderr)
        return 2

    pin = os.environ.get(args.pin_env)

    with tempfile.TemporaryDirectory() as td:
        msg_path = os.path.join(td, "msg.bin")
        sig_path = os.path.join(td, "sig.bin")
        with open(msg_path, "wb") as f:
            f.write(msg)

        cmd = [
            "pkcs11-tool",
            "--module", args.module,
            "--slot", str(args.slot),
            "--sign",
            "--mechanism", args.mechanism,
            "--id", args.key_id,
            "--input-file", msg_path,
            "--output-file", sig_path,
        ]
        if pin:
            cmd.extend(["--pin", pin])

        try:
            proc = subprocess.run(cmd, capture_output=True, check=False)
        except FileNotFoundError:
            print("ERROR: pkcs11-tool not found (install opensc)", file=sys.stderr)
            return 127

        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", errors="replace").strip()
            stdout = proc.stdout.decode("utf-8", errors="replace").strip()
            print("ERROR: pkcs11-tool failed", file=sys.stderr)
            if stdout:
                print(stdout, file=sys.stderr)
            if stderr:
                print(stderr, file=sys.stderr)
            return proc.returncode or 1

        try:
            with open(sig_path, "rb") as f:
                sig = f.read()
        except FileNotFoundError:
            print("ERROR: signature output not produced", file=sys.stderr)
            return 1

    sys.stdout.write(base64.b64encode(sig).decode("ascii"))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
