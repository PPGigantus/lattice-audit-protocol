# Go Reference Verifier (lapverify)

This directory contains a minimal, dependency-free Go reference verifier for LAP.

Commands:

- `lapverify vectors <dir>`: verify `spec/test_vectors`
- `lapverify audit-pack <zip-or-dir> [--require-invocations]`: verify a golden audit pack

Example (from repo root):

```bash
go run ./go/lapverify/cmd/lapverify vectors spec/test_vectors
go run ./go/lapverify/cmd/lapverify audit-pack spec/golden_packs/golden_pack_basic.zip --require-invocations
```
