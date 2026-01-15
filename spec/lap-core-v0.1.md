# LAP Core v0.1 (Freeze Candidate)

This document is the **freeze candidate** for a minimal, interoperable “LAP Core”
that other implementations can target (Python, Go, Rust, TS, etc).

It intentionally focuses on **wire formats + verification rules**, not deployment
details.

If you implement only this document (plus referenced schemas/vectors), you can:
- generate evidence/decision/receipt artifacts
- package them into an audit pack
- verify everything offline, deterministically

## Scope

LAP Core v0.1 includes:

1. **Canonical JSON v2** used for hashing JSON objects.
2. **Hash definitions** for Evidence, Params, Receipt-chain, and Audit Pack.
3. **Signature payload definitions** (what bytes get signed).
4. **Artifact schemas** (JSON Schemas under `spec/schemas/`).
5. **Verification requirements** (what MUST be accepted/rejected).
6. **Stable error codes** for machine handling (`spec/ERROR_CODES.md`).
7. **Conformance vectors** (`spec/test_vectors/` + `lap-conformance` runner).

Everything else (policy logic, UI, storage engines, specific gateways) is an
**extension**.

## Normative references

- Canonical JSON: `spec/CANONICAL_JSON.md`
- Stable core surface (hashes, signature payloads): `spec/STABLE_CORE.md`
- Schemas: `spec/schemas/`
- Interop vectors: `spec/test_vectors/`
- Golden packs: `spec/golden_packs/`

In case of conflict, **this document + STABLE_CORE.md** are normative, and
implementations MUST match the shipped vectors.

## Canonical JSON requirements (summary)

Implementations MUST canonicalize JSON objects using **Canonical JSON v2**:

- Strict JSON: reject NaN/Infinity and non-JSON types (no implicit stringification)
- Unicode normalization: normalize all strings **and dict keys** to **NFC**
- Key-collision defense: if normalization collapses keys, verification MUST fail
- DoS guards (implementation constants, but MUST be enforced):
  - max nesting depth (default 64)
  - max integer digit length (default 128)
  - (recommended) max container length and max total nodes

See `spec/CANONICAL_JSON.md` for the exact algorithm.

## Conformance

A compliant implementation MUST pass:

- `lap-conformance` (vectors + golden pack verification)
- Schema validation for all shipped artifacts
- Receipt-chain integrity checks

## Versioning

- This document is **v0.1**. Backwards-incompatible changes require a new
  major core version.
- Artifacts include explicit `schema_version` fields; verifiers MUST reject
  unknown major versions unless explicitly configured to allow them.
