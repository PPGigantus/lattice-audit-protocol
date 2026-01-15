# Lattice Audit Protocol (LAP) Threat Model

This document defines the **security boundary**, **attacker capabilities**, and **inductive invariants** that LAP is intended to enforce.

LAP is best understood as **governance + enforcement infrastructure** for agent/tool execution. It is not a complete solution to inner alignment, deception, or value learning; it focuses on *non-bypassable enforcement* (to the extent permitted by the assumed boundary) and *tamper-evident auditability*.

For a plain-English summary of **what LAP guarantees** (and what it does not), see [`CLAIMS.md`](CLAIMS.md).

## 1. System components

- **Gateway (PEP)**: policy enforcement point that issues/validates capability tokens and produces receipts.
- **Auditor(s) (PDP)**: policy decision point(s) that evaluate requested actions and produce decisions.
- **Store**: persistence for budgets, replay prevention, decisions, approvals, and audit logs.
- **Signer**: cryptographic authority used to sign receipts and tokens.
- **Verifier**: offline verifier (e.g., `lap-verify`) that checks tokens/receipts/audit packs.

## 2. Trust boundaries

LAP can be deployed with different boundaries. The strongest claims require a strong signer boundary.

### 2.1 Baseline boundary (software signer)
Assumptions:
- The Gateway process and its memory are part of the trusted computing base (TCB).
- The signer private key is present in Gateway memory (or on disk readable by the Gateway).

Claims possible under this boundary:
- **Tamper-evidence** and **consistency** for well-behaved deployments.
- Strong *engineering* fail-closed posture (e.g., lockdown on storage degradation).

Limits:
- An attacker with OS root can extract keys and forge receipts/tokens.

### 2.2 Strong boundary (hardware-backed signer)
Assumptions:
- The signer private key is **non-exportable** (TPM/HSM/secure enclave).
- Gateway can request signing, but cannot read the private key.
- Offline verifiers trust the public key and reject anything not signed by it.

Claims under this boundary:
- Even with OS root on the Gateway host, an attacker **cannot forge** receipts/tokens **unless** they can cause the hardware signer to sign unauthorized payloads.

Limits:
- Root can still cause denial-of-service, censor logging, or prevent actions.
- Root can still modify policy code; the key protection only prevents *forgery*, not *availability*.

## 3. Attacker models

### A0: External unauthenticated attacker
- Can send requests to the Gateway endpoint.
- Goal: trigger tool actions, exhaust budgets, replay tokens, DoS the Gateway.

### A1: Authenticated but malicious caller
- Has a valid token (maybe stolen) and tries to exceed budget or bypass constraints.

### A2: Compromised client / prompt injection
- Attempts to smuggle destructive intent through benign wrappers.

### A3: Compromised store / partial infrastructure failure
- Store locks, becomes slow/unresponsive, or returns errors.

### A4: OS root compromise on Gateway host
- Can read/modify Gateway process memory, code, and local disk.
- Under baseline boundary, this breaks cryptographic guarantees.
- Under hardware-backed signer boundary, forging remains difficult.

## 4. Security goals (what LAP tries to guarantee)

### G1 — Non-bypassable enforcement (within boundary)
Actions requiring authorization are denied unless the required decision/approvals are present.

### G2 — Budget safety
Authorized budget is not exceeded by any allowed sequence of operations (no double-spend).

### G3 — Replay prevention
A capability token cannot be reused beyond its intended nonce/counter constraints.

### G4 — Tamper-evident audit
Receipts and audit packs allow an offline verifier to confirm what was authorized and what was returned.

### G5 — Fail-closed under degraded state
If storage is slow/unresponsive/locked, the system becomes **more restrictive** (lockdown), never less restrictive.

## 5. Inductive invariants (intended to hold in all states)

The following invariants should hold across all interleavings and crash/recovery cycles.

### I1 — Budget conservation
For each budget domain:
- `spent + reserved <= authorized`
- `spent` is monotonically non-decreasing
- `reserved` is monotonically non-negative

### I2 — No double-spend
A unit of budget cannot be spent twice. Each spend must correspond to an earlier reservation.

### I3 — Replay safety
For each token `jti`:
- A `nonce` may be used at most once.
- `counter` must be strictly increasing.

### I4 — Receipt commitment
Each receipt commits (by hash) to:
- the decision/policy context
- request params
- the response envelope actually returned (`success`, `result`, `error`)

### I5 — Lockdown monotonicity
When the store is unhealthy:
- The Gateway transitions into `LOCKDOWN`.
- While in `LOCKDOWN`, operations that would spend budget or mint new capabilities are denied.

### I6 — Dual-auditor consensus (when configured)
For high-severity actions (e.g., T3), minting requires:
- at least N approvals from distinct roles (e.g., `PrimaryDecider` and `SafetyCritic`)
- approvals are cryptographically verified

### I7 — Reviewer override for low-quality evidence (when configured)
If evidence is flagged as low-entropy / semantically minimal:
- minting must be denied unless a dedicated `ReviewerOverride` approval is present.

## 6. What this does NOT guarantee

- It does not solve deception/inner alignment.
- It does not guarantee the model will *choose* safe actions; it constrains what actions are executable.
- It does not prevent an OS-root attacker from **denying service**.
- Under baseline boundary, it does not prevent a root attacker from forging receipts/tokens.

## 7. Verification plan

- Unit tests for budget and replay logic.
- Adversarial tests for prompt injection patterns.
- Offline verification (`lap-verify`) for receipts/audit packs.
- Formal model checking for the budget state machine (TLA+/P) to validate invariants I1–I3 and I5 across crash/recovery interleavings.