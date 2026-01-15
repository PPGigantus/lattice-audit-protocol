# LAP Stable Core (v1)

This document defines the **Minimum Stable Core** of the Lattice Audit Protocol (LAP).

If LAP becomes a standard, this is what other implementations (in other languages/runtimes) should be able to rely on as **stable**. Anything not listed here is considered an **extension** or an **implementation detail**.

## Stable Core surface

The Stable Core is the **interoperability + verification contract**:

1. **Canonical JSON rules** used for hashing JSON objects.
2. **Hash definitions** (what gets hashed, how, and what the outputs mean).
3. **Signature payload definitions** for tokens, external approvals, and receipts.
4. **Artifact schemas** (Evidence, Decision, Token, Receipt, ExternalApproval, AuditPack manifest).
5. **Verification requirements** (what a verifier MUST reject / accept).
6. **Key IDs (kid)** and keyset behavior for verification.

## 1) Canonical JSON

LAP Canonical JSON v1 is defined in `spec/CANONICAL_JSON.md`.

**Stable requirement:** any field that is hashed via “canonical JSON” MUST be hashed using exactly that canonicalization, and verifiers MUST compute hashes from canonicalized JSON (not raw bytes).

## 2) Hashes

### Evidence hash

`evidence_hash = SHA256( CanonicalJSON(evidence_object) )` (hex string).

### Params hash (binding tool parameters)

`params_hash = SHA256( CanonicalJSON(params_object) )` (hex string).

### Decision hash

Decision hash is **not** JSON-hashed. It is a length-prefixed string encoding:

`decision_hash = SHA256( SafeHashEncode([action_id, evidence_hash, outcome, tier, reason]) )` (hex string).

Where `SafeHashEncode` concatenates each string component as:

- 8-byte big-endian length prefix
- UTF-8 bytes of the string

This is intentionally delimiter-safe.

### Receipt hash

Receipts include an integrity hash computed as:

`receipt_hash = SHA256( SafeHashEncode([...receipt fields...]) )` (hex string)

Exact field order is defined by the receipt implementation (`ToolInvocationReceipt.compute_receipt_hash`).

## 3) Signature payloads

All signatures are Ed25519 over a deterministic byte payload.

### Capability Token signature payload

A token signature payload is:

`SafeHashEncode([jti, sub, iss, action_id, evidence_hash, decision_hash, tier, sorted(allowed_tools), sorted(allowed_ops), budget_json, iat, exp, params_hash, sid, nonce_required, counter_required])`

Where `budget_json` is `json.dumps(budget.to_dict(), sort_keys=True)`.

### External Approval signature payload

Defined by `Ed25519ExternalApproval.compute_signature_payload` (length-prefixed string encoding).

### Receipt signature payload

Defined by `ToolInvocationReceipt.compute_signature_payload` (length-prefixed string encoding).

## 4) Schemas

The authoritative schemas live in `spec/schemas/`.

Stable schema set:
- `evidence.schema.json`
- `decision.schema.json`
- `token.schema.json`
- `receipt.schema.json`
- `external_approval.schema.json`
- `audit_pack_manifest.schema.json`
- `trusted_keys.schema.json`

## 5) Verification requirements

A conforming verifier **MUST**:

- Recompute `evidence_hash` from canonical JSON and compare to the manifest.
- Recompute `decision_hash` from the defined components and compare to the manifest.
- Verify Ed25519 signatures for any included signed artifacts (unless explicitly running in a “skip signatures” mode).
- Enforce bindings:
  - Token must bind to `{action_id, evidence_hash, decision_hash}`.
  - Receipts must bind to `{action_id, evidence_hash, decision_hash}`.
  - Receipt chains must be intact (`prev_receipt_hash` matches).
- Fail closed: any missing required artifact or parse/verification error is a failure.

## 6) Key IDs and keysets

Artifacts carry a `key_id` (kid). Verification uses a **trusted keyset** mapping `key_id -> public key`.

During key rotation, verifiers MAY accept multiple `key_id`s (old + new). The stable contract is that:

- Signed artifacts include `key_id`.
- Trusted keysets MAY contain multiple keys.

## What’s explicitly NOT stable

These are intentionally left as extensions/implementation details:

- Policy logic beyond the hashed/signed artifacts.
- Runtime deployment topology (sidecar vs hosted vs OS-layer).
- Rate limiting strategy (in-process, proxy, redis, WAF, etc.).
- Storage backend details.
- Observability tooling.

