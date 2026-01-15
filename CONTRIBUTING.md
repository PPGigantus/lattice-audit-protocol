# Contributing

Thanks for taking a look at **Lattice Audit Protocol (LAP)**.

This repo is intentionally opinionated: it aims to be a **Policy Decision Point (PDP)** + **Policy Enforcement Point (PEP)** reference implementation that is:

- **fail-closed** under uncertainty or degraded storage
- **cryptographically verifiable** (signed tokens + receipts)
- **hard to bypass inside a defined boundary** (gateway holds tool creds)

If you want to help, the most valuable contributions are:

- adversarial reviews of bypass paths (replay, identity spoofing, confused-deputy)
- tests that lock in fail-closed behavior
- clearer docs + threat model clarifications
- integration adapters (HTTP tools, queues, policy engines), behind feature flags

---

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e " .[gateway,dev] "
```

Run tests:

```bash
pytest -q
```

Optional: run the gateway locally:

```bash
python -m lap_gateway.server --host 127.0.0.1 --port 8000
```

---

## What to change (and what not to)

### ✅ Good changes

- add/strengthen **security invariants** (fail closed, no silent approval)
- add tests for:
  - session binding (T2/T3)
  - nonce/counter replay resistance (T2/T3)
  - budget enforcement
  - denial receipts + signature verification
- improve determinism of hashes / signature payloads
- improve the demo boundary patterns (Docker, Kubernetes, sidecar designs)

### ⚠️ Be careful with

- anything that changes default allow/deny outcomes
- anything that weakens boundary assumptions (e.g. moving tool creds outside the gateway)
- relaxing evidence validation for high tiers

### ❌ Avoid

- adding new dependencies unless there is a strong reason
- enabling network tool connectors by default

---

## Pull request checklist

- [ ] Tests added/updated
- [ ] No new fail-open paths introduced
- [ ] Docs updated (README / THREAT_MODEL / CHANGELOG)
- [ ] Security-sensitive changes include a brief threat analysis in the PR description

---

## Security issues

Please **do not** open a public issue for a security vulnerability.

Instead, follow `SECURITY.md`.
