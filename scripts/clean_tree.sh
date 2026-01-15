#!/usr/bin/env bash
set -euo pipefail

# Clean build/runtime artifacts from the repo tree.
# Intended for local hygiene and CI/release packaging.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Python caches
find . -name '__pycache__' -type d -prune -exec rm -rf {} +
find . -name '*.pyc' -delete

# Test/coverage artifacts
rm -rf .pytest_cache .coverage htmlcov .mypy_cache .ruff_cache .hypothesis

# Build artifacts
rm -rf dist build
find . -maxdepth 2 -name '*.egg-info' -type d -prune -exec rm -rf {} +

# Demo output
rm -rf demo/out

# LAP runtime artifacts
rm -f lap_gateway.db lap_gateway.audit.jsonl
