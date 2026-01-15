# Security Review Pack

This repository implements the **Lattice Audit Protocol (LAP)**: a policy-enforced gateway (PEP) with verifiable,
offline audit artifacts (receipts, tokens, attestations, audit packs).

This document is intended to help external reviewers quickly understand:
- trust boundaries and assumptions,
- the main attack surfaces,
- what security claims LAP does and does not make,
- how to reproduce the key tests.

## Architecture and trust boundaries

High-level control flow:

1. **Client** submits evidence for a proposed tool action.
2. **PDP** (policy decision point) evaluates evidence and returns a decision.
3. **Gateway / PEP** (policy enforcement point) enforces that decision:
   - checks budgets, replay constraints, and binding invariants,
   - invokes the tool only if allowed,
   - emits signed receipts and (optionally) signed attestations.
4. **Audit pack** exporter bundles receipts/tokens/attestations + schemas + manifest for offline verification.

Trust boundaries (what must be true for enforcement claims to hold):

- **Tool credentials must exist only behind the gateway.**
  If the agent can call tools directly, LAP becomes logging/auditability, not enforcement.
- **Signer integrity matters.**
  If an attacker can sign arbitrary receipts (stolen keys), they can forge audit artifacts. Use non-exportable keys
  (TPM/HSM/secure enclave) via the external-signer seam when possible.
- **Storage integrity affects liveness.**
  LAP is designed to fail closed (lockdown) when it cannot reliably persist or advance monotonic state.

## Key security claims (summary)

For the precise statement of claims and non-claims, see **CLAIMS.md**.

In short, within the stated boundary:
- tool invocations are **policy-gated** by the gateway,
- emitted receipts and attestations are **tamper-evident** (signed),
- replay/substitution is prevented by **binding invariants** and monotonic counters,
- audit packs can be **verified offline** against included schemas and public keys.

## Main attack surfaces to review

1. **Bypass of the gateway boundary**
   - Can the agent reach the tool endpoints directly?
   - Can the agent obtain tool credentials?

2. **Signature verification / canonicalization ambiguity**
   - Does canonical JSON encoding produce the same bytes across implementations?
   - Are all signature payloads unambiguous and fully specified?

3. **Replay and substitution**
   - Can a valid decision/token be reused with different params?
   - Can receipts be spliced across sessions/actions?

4. **Key lifecycle**
   - Rotation/revocation behavior
   - Unknown/revoked key handling

5. **Degraded mode / fail-closed behavior**
   - What happens when signer/PDP/storage are down?
   - Is it possible to execute a tool without producing a signed receipt?

## How to reproduce core verification flows

### Quick demo (end-to-end)
See README “Run demo” and “Verify audit pack”.

### Offline verification
Run:
- `python lap_verify.py <audit-pack-dir-or-zip> --trusted-keys <keys.json>`

### Go verifier (interop)
Run:
- `go run ./go/lapverify/cmd/lapverify <audit-pack> --trusted-keys <keys.json>`

## Reviewer checklist

- [ ] Attempt to bypass gateway in the provided reference deployment (K8s network policy).
- [ ] Verify signature payload definitions match schema and manifest version fields.
- [ ] Confirm `canonical_json_version` and `receipt_profile` are enforced by verifiers.
- [ ] Validate replay/substitution tests cover token/decision/action binding.
- [ ] Confirm external signer seam fails closed when unavailable.
- [ ] Confirm audit pack exporter rejects inconsistent hashes (manifest vs token/receipts).
