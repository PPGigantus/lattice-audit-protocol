#!/usr/bin/env bash
set -euo pipefail

# PKCS#11 external signer wrapper (reference).
# Reads message bytes from stdin, writes base64 signature to stdout.
#
# Usage:
#   pkcs11_signer.sh --module /path/to/module.so --slot 0 --key-id 01 [--pin-env PKCS11_PIN] [--mechanism EDDSA]

MODULE=""
SLOT=""
KEY_ID=""
PIN_ENV="PKCS11_PIN"
MECH="EDDSA"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --module) MODULE="$2"; shift 2 ;;
    --slot) SLOT="$2"; shift 2 ;;
    --key-id) KEY_ID="$2"; shift 2 ;;
    --pin-env) PIN_ENV="$2"; shift 2 ;;
    --mechanism) MECH="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$MODULE" && -n "$SLOT" && -n "$KEY_ID" ]] || { echo "Missing required args" >&2; exit 2; }

PIN="${!PIN_ENV:-}"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT
MSG="$TMPDIR/msg.bin"
SIG="$TMPDIR/sig.bin"

cat > "$MSG"

CMD=(pkcs11-tool --module "$MODULE" --slot "$SLOT" --sign --mechanism "$MECH" --id "$KEY_ID" --input-file "$MSG" --output-file "$SIG")
if [[ -n "$PIN" ]]; then
  CMD+=(--pin "$PIN")
fi

"${CMD[@]}" >/dev/null 2>&1 || { echo "ERROR: pkcs11-tool signing failed" >&2; exit 1; }

python3 - <<'PY'
import base64, sys
with open(sys.argv[1],'rb') as f:
    sys.stdout.write(base64.b64encode(f.read()).decode('ascii'))
PY "$SIG"
