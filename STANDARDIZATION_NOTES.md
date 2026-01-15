# Standardization Notes

This document is a practical guide for evolving LAP into something other teams can safely adopt.

## What should be standardized

### 1) Canonical primitives

- **Evidence hash**: deterministic hash of the evidence object used for evaluation
- **Decision hash**: deterministic hash of (action_id + evidence_hash + outcome + tier + reason)
- **Capability token**: signed, budgeted, time-limited authorization bound to decision hash
- **Receipts**: signed invocation/denial artifacts for audit trails

If other implementations exist, they should agree on:

- canonical JSON serialization rules

Recommended v2 hardening constraints:
- Unicode normalization (NFC) for strings and dict keys
- Maximum nesting depth (default 64)
- Preserve JSON integers exactly; implementations must avoid float64 coercion for large integers (Python enforces a digit-length limit to prevent DoS)

- signature payload ordering
- timestamp formats (ISO-8601 UTC)

### 2) A minimal “PEP contract”

A PEP should expose (names are illustrative):

- `POST /session/new`  → session id (gateway-issued)
- `POST /evaluate`     → outcome + constraints + token (or escrow)
- `POST /tools/{tool}/invoke` → execute tool under token + budgets + replay defenses

### 3) A minimal “PDP contract”

A PDP should be allowed to vary, but it must output:

- tier, outcome, reason
- constraints/budgets (or references)
- decision hash binding material

## Extension points (where diversity is good)

- evidence schemas (domain-specific fields)
- external approvals / human review channels
- tool adapters (HTTP, queues, RPC)
- anchoring (timechains, transparency logs)

## Compatibility principle

Default behavior should remain:

- **fail closed** on missing info, degraded storage, or signature verification failure
- **no high-tier execution without strong caller identity**
- **no T2/T3 without gateway-issued sessions + replay controls**

## Suggested “interoperability tests”

- token verification across two implementations (same signing key)
- decision hash matches across implementations
- budget enforcement consistency
- replay defense consistency (nonce + counter)


## HTTP transparency backend (optional)

LAP can compute transparency anchors (hashes) for receipts / DSSE envelopes / audit packs via `lap anchor`.
By default, anchors are written locally as JSONL.

PR-016 adds an **opt-in** HTTP push backend:

- `lap anchor <pack> --out anchors.jsonl --push https://example/anchors`
- Use `--mode hash-only` (default) to publish only hashes and timestamps.
- Use `--mode metadata` to include `key_id`, `signature`, and optional `gateway_id`.

Failure behavior:
- If `--required` is set (or `ANCHOR_REQUIRED=true`), push failures are treated as errors (fail closed).
- Otherwise push failures are logged and local anchoring still succeeds.

