# LAP Claims and Boundary Assumptions

This document is a plain‑English taxonomy of what the Lattice Audit Protocol (LAP) **does** and **does not** guarantee.
LAP’s guarantees are **conditional**: they hold only within a clearly defined deployment boundary.

---

## What LAP Guarantees (within the boundary)

If (and only if) tool execution is forced through the LAP Gateway/PEP and the signing/identity assumptions below hold, LAP provides:

- **Policy-gated tool execution:** the gateway will allow or deny a tool call based on a verifiable decision/token, and **fail closed** when required checks can’t be satisfied.
- **Bounded capability use:** capability tokens can be bound to a specific action/tool/operation (and for high-stakes, specific parameters), limiting reuse outside the approved intent.
- **Budget enforcement:** per-token budgets (calls, bytes, duration, spend) are enforced at the gateway, not by the agent.
- **Replay resistance:** nonce (T2/T3) and counter (T3) requirements reduce replay/duplication of approved capabilities.
- **Session/identity binding (when enabled):** higher-tier actions can require authenticated identity and a gateway-issued session, reducing “header spoofing” classes of mistakes.
- **Tamper-evident records:** the gateway emits **signed receipts** and maintains a **hash-chained audit log** so post-hoc alteration is detectable.
- **Offline verification:** third parties can verify tokens/receipts/audit packs using published schemas, canonicalization rules, and test vectors.

---

## What LAP Does NOT Guarantee

LAP is an enforcement + auditability layer, not a general safety solution. It does **not** guarantee:

- **Alignment or correctness of the policy.** If the PDP’s decision logic is wrong, LAP will faithfully enforce the wrong decision.
- **Safety outside the boundary.** If an agent can reach tools directly (or has credentials), it can bypass LAP.
- **Security under host compromise.** If the gateway host/container is compromised, an attacker may exfiltrate secrets, tamper with runtime state, or deny service.
- **Protection after key theft.** If signing keys are stolen, attackers may forge tokens/receipts until keys are rotated and verifiers update trusted keysets.
- **Truthfulness of evidence.** LAP can bind decisions to evidence artifacts, but it cannot prove that evidence is honest, complete, or non-deceptive.
- **Confidentiality by itself.** If a permitted tool call returns sensitive data, LAP will not prevent exposure unless policy/budgets/egress controls do.
- **Availability.** DoS, resource exhaustion, or upstream outages can still prevent correct operation (LAP can “fail closed,” but that may look like downtime).

---

## Required Deployment Assumptions

To rely on LAP’s guarantees, you must enforce these assumptions:

- **Tool credentials live only in the gateway.** Agents must not have direct tool secrets (API keys, tokens, cloud creds).
- **No direct tool path from agents.** Network policy must ensure agents cannot reach tool endpoints except via the gateway.
- **Egress controls for agents.** “Agent container has no internet” (or strict allowlist) is the default-safe posture.
- **Gateway ingress is controlled.** Put the gateway behind a reverse proxy/LB; enforce TLS, request limits, and authentication.
- **Signer integrity.** The signing key (or external signer) must be protected against extraction/tampering.
- **Clock/time assumptions are explicit.** If you rely on expiry windows, ensure stable time sources and document drift tolerance.
- **Audit log durability.** Audit logs/receipts must be stored durably (and ideally exported/archived) to preserve forensic value.

---

## Security Modes: Soft keys vs Hard keys

LAP can be deployed with different “signing boundary” strengths:

### Soft keys (baseline)
Signing keys are loaded from env/file and used in-process by the gateway.

- **Pros:** simplest to deploy; good for dev/single-host demos.
- **Cons:** if the gateway host is compromised, keys are likely extractable; forged artifacts are plausible.

### Hard keys (recommended for serious deployments)
Signing is performed by a TPM/HSM/KMS or an external signer process with strict access controls.

- **Pros:** key extraction becomes much harder; forging tokens/receipts without signer access is significantly reduced.
- **Cons:** more operational complexity; requires rotation playbooks and signer availability planning.

**What changes:** Hard-key mode primarily strengthens the *integrity of signatures and receipts*. It does not, by itself, prevent bypass if tools remain reachable outside the gateway or if credentials leak to the agent.
