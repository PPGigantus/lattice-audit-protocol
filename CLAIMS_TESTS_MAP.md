# Claims-to-Tests Mapping

This table maps LAP's high-level claims to concrete tests and reproduction steps.

For the canonical statement of claims, see **CLAIMS.md**.

| Claim | Evidence (tests / scripts) | How to run |
|------|-----------------------------|------------|
| Offline verification detects tampering (signatures) | `tests/test_verify_offline.py`, `lap_verify.py`, `spec/schemas/*.json` | `pytest -q` and `python lap_verify.py <pack> --trusted-keys <keys.json>` |
| Canonical JSON version is explicit and enforced | `tests/test_canonical_json.py`, `spec/CANONICAL_JSON.md`, manifest `canonical_json_version` | `pytest -q` |
| Receipt/token binding prevents substitution | `tests/test_replay_hotpath.py`, `tests/test_audit_pack_hash_authority.py`, receipt `decision_binding` | `pytest -q` |
| Receipt chains detect splicing (per action) | `tests/test_receipt_chain.py` (or `tests/test_load_and_chaos.py`), receipt `prev_receipt_hash` | `pytest -q` |
| Fail-closed on signer outage (no tool exec without signer) | `tests/test_load_and_chaos.py` (signer-down mode), gateway signer precheck | `pytest -q` |
| Key rotation/revocation enforced by verifier | `tests/test_keys_rotation.py`, `lap_gateway/crypto.py` | `pytest -q` |
| Audit pack export rejects inconsistent hashes | `tests/test_audit_pack_hash_authority.py`, `lap_gateway/audit_pack.py` | `pytest -q` |
| Go verifier passes golden packs (interop proof) | `.github/workflows/go-verify.yml`, `go/lapverify/...` | `go test ./...` and run verifier on golden pack |
