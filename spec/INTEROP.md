# LAP Interoperability Compliance Kit

A minimal, dependency-free Go reference verifier lives in `go/lapverify/`.
It is intended to validate canonicalization and hashing rules across languages.

This document defines a **minimum interoperability surface** for the Lattice Audit Protocol (LAP).

If you implement LAP in another language/runtime (Rust, Go, JS, JVM, etc.), the goal is that:
- hashes match across implementations
- tokens/receipts verify offline
- audit packs are portable and machine-verifiable

The keywords **MUST**, **SHOULD**, and **MAY** are used as in RFC 2119.

---

## 1) Canonical JSON

Implementations **MUST** produce canonical JSON exactly as described in `spec/CANONICAL_JSON.md`.

In particular, canonical JSON:
- **MUST** sort keys deterministically
- **MUST** use separators with **no whitespace** (`","` and `":"`)
- **MUST** serialize as UTF-8 and **MUST NOT** escape unicode (`ensure_ascii=false` semantics)
- **SHOULD** use a deterministic `default=str`-style fallback for non-JSON-native values (timestamps, decimals) *only if needed*

If canonical JSON differs, all downstream hashes and signatures will diverge.

---

## 2) Hashes

### Evidence hash
- The evidence hash **MUST** be:
  - `sha256_hex(canonical_json(evidence_object))`

### Decision hash
- The decision hash **MUST** be:
  - `sha256_hex( safe_hash_encode([
      action_id,
      evidence_hash,
      outcome,
      tier,
      reason
    ]))`

Where `safe_hash_encode` is a length-prefixed concatenation of UTF-8 strings (see `lap_gateway.crypto._safe_hash_encode`).

### Params / result / response hashes
- When `invocations.json` is present, each receipt’s:
  - `params_hash` **MUST** match `sha256_hex(canonical_json(invocation.params))`
  - `result_hash` **MUST** match `sha256_hex(canonical_json(invocation.result))`
  - `response_hash` **MUST** match `sha256_hex(canonical_json(invocation.response_envelope))`

---

## 3) Signatures

- Tokens and receipts **MUST** use **Ed25519** signatures.
- The signing payload **MUST** be computed exactly as in the reference implementation:
  - token: `CapabilityToken.compute_signature_payload()`
  - receipt: `ToolInvocationReceipt.compute_signature_payload()`
- Verifiers **MUST** reject signature mismatches unless explicitly configured to skip signature checks.

---

## 4) Audit packs

An **audit pack** is a portable `.zip` (or directory) containing:

### Required files
- `manifest.json`
- `evidence.json`
- `decision.json`
- `receipts.json` (may be an empty list)
- `trusted_keys.json` (may be empty)

**Key rotation:** `trusted_keys.json` is a keyset (map of `key_id` → `public_key_hex`). It MAY contain multiple gateway keys so verifiers can accept packs created before/after a rotation. Tokens/receipts MUST include `key_id` so verifiers know which key to select.

### Optional files
- `token.json`
- `external_approval.json`
- `invocations.json` (recommended; enables hash-commit verification)
- `anchor.json`

Implementations **SHOULD** include `invocations.json` for any action where replay-proof, tamper-evident tool I/O matters.

---

## 5) Compliance commands

Reference tooling included in this repo:

```bash
# Verify interoperability vectors
lap-verify vectors spec/test_vectors

# Verify an audit pack (.zip or directory)
lap-verify audit-pack path/to/audit_pack.zip --require-invocations

# Validate artifacts and packs against JSON Schemas
lap schema-validate spec/test_vectors/evidence_basic.json
lap schema-validate spec/golden_packs/golden_pack_basic.zip
```

---

## 6) Test fixtures

### Interop vectors
- Location: `spec/test_vectors/`
- Purpose: cross-language determinism checks (hashes, token/receipt signatures)

### Golden audit packs
- Location: `spec/golden_packs/`
- Purpose: end-to-end offline verification of a full portable pack

Implementations **SHOULD** use both sets of fixtures during CI.
