#!/usr/bin/env bash
set -euo pipefail

# Simple developer sanity checks (PR-000)

python -m compileall .
python -m pytest -q

# Quick schema validation smoke test (validates a known-good fixture)
python -m lap_schema_validate spec/test_vectors/receipt_basic.json

echo "OK: dev checks passed"
