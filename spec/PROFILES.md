# LAP Compliance Profiles

LAP is designed to be adopted incrementally. This document defines **compliance profiles** that implementations and deployments can claim.

Profiles are verified by the offline verifier:

```bash
lap-verify profile bronze <path>
lap-verify profile silver <profile_attestation.json>
lap-verify profile gold <profile_attestation.json>
```

## Bronze: Interop / SDK profile

Bronze is about **portable artifacts** and **independent verification**.

Bronze requires:
- Published schemas (`spec/schemas/*`) and canonicalization rules (`spec/CANONICAL_JSON.md`).
- Deterministic interop fixtures (`spec/test_vectors/*`) and at least one golden audit pack (`spec/golden_packs/*`).
- An offline verifier that can:
  - validate schemas
  - recompute hashes
  - verify signatures
  - verify golden audit packs

How verification works:
- `lap-verify profile bronze spec/test_vectors` will verify the vectors.
- `lap-verify profile bronze spec/golden_packs/golden_pack_basic.zip` will validate + verify the pack.

## Silver: Sidecar enforcement profile

Silver is about **enforcement** (a PEP / sidecar / daemon) with auditable receipts.

Silver requires, at minimum:
- Token signature verification (fail-closed).
- Replay prevention (nonce/counter and/or server-side replay store).
- Budget enforcement for tool calls.
- Session binding for higher tiers.
- Signed receipts and a tamper-evident audit log.
- Documented trust boundary: the sidecar is the only holder of tool credentials.

How verification works:
- Silver is verified via a deployment attestation JSON (see `spec/profile_attestations/*`).

## Gold: Hardened production profile

Gold is about **hardening and deployment safety**.

Gold requires, at minimum:
- External signing or protected key handling (HSM/KMS or signer process), plus key rotation support.
- Separation-of-duties for catastrophic tier actions (multi-party review / override process).
- Boundary isolation patterns (network policies / container nets) preventing agents from reaching tools directly.
- Strict mode for protocol engine loading (no silent fallback in production).
- Stronger identity binding (OIDC/JWT or mTLS) OR well-scoped API keys with rotation.

How verification works:
- Gold is verified via a stricter deployment attestation JSON.

## Profile attestations

Profile attestations are JSON files validated against `spec/schemas/profile_attestation.schema.json`.

Examples:
- `spec/profile_attestations/silver_example.json`
- `spec/profile_attestations/gold_example.json`

The intent is pragmatic: verifiers can mechanically check a claimed profile in CI, while operational audits can validate the claim.
