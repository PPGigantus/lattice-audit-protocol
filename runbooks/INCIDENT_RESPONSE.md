# Incident Response (LAP Gateway)

This runbook is for operational incidents affecting the LAP Gateway (PEP) and related components (PDP, signer, storage).

## Primary principle: fail closed
If any critical dependency is degraded, the gateway should deny tool execution rather than allow it.

## 0) Quick triage checklist
- Confirm scope: single agent / single tool / global?
- Check `/v1/health` and `/v1/stats` (if enabled).
- Inspect gateway logs for: `LOCKDOWN_ACTIVE`, `PDP_ERROR`, `SIGNER_UNAVAILABLE`, `RATE_LIMITED`.
- Verify whether tools are bypassable (network paths, leaked credentials).

## 1) Containment actions
- If you suspect bypass: revoke tool credentials and rotate immediately.
- If signer is compromised: rotate keys, invalidate trust roots, and reissue trusted key config.
- If storage is degraded: enable lockdown (or lower thresholds) until DB is healthy.

## 2) Evidence preservation
- Export an audit pack for the affected action(s).
- Preserve:
  - receipts/tokens/attestations packs
  - gateway logs (with timestamps)
  - PDP logs/config (policy versions)

## 3) Communication
- Declare incident severity and current fail-closed mode.
- Provide timeline: first detection, containment start, mitigation, resolution.

## 4) Postmortem
- Root cause + contributing factors
- Detection gaps
- Concrete follow-ups:
  - tests to prevent regression
  - CI harness updates
  - runbook improvements
