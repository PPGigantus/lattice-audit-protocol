#!/usr/bin/env bash
set -euo pipefail

CN="localhost"
OUT="deploy/certs"
DAYS=365

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cn) CN="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --days) DAYS="$2"; shift 2;;
    *) echo "Unknown arg: $1"; exit 2;;
  esac
done

mkdir -p "$OUT"

openssl req -x509 -newkey rsa:2048 -sha256 -days "$DAYS" -nodes \
  -keyout "$OUT/privkey.pem" \
  -out "$OUT/fullchain.pem" \
  -subj "/CN=$CN"

echo "Wrote: $OUT/fullchain.pem and $OUT/privkey.pem"
