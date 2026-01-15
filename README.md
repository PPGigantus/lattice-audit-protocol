# Lattice Audit Protocol (LAP) — v1.4.1
LAP is a **governance + enforcement** framework for high-stakes AI/agent tool use.

It is designed around a clean split:

- **PDP (Policy Decision Point)** — evaluates an action request and produces a decision, constraints, and (optionally) an authorization token.
- **PEP (Policy Enforcement Point / Gateway)** — the execution choke-point that **holds tool credentials**, **verifies tokens**, enforces **budgets**, prevents **replay**, and emits **signed receipts**.

> LAP is not “inner alignment.” It’s an enforcement + auditability layer that makes tool execution **policy-gated**, **budgeted**, and **cryptographically verifiable** — inside a clearly stated deployment boundary.

**Start here:** [`CLAIMS.md`](CLAIMS.md) — what LAP guarantees (and does *not*), plus the required deployment assumptions.

Related docs: [`THREAT_MODEL.md`](THREAT_MODEL.md), [`DEPLOYMENT.md`](DEPLOYMENT.md).

## Adoption kit demo (end-to-end)

This repo includes a deterministic local demo that:
- starts the gateway and a tiny HTTP tool service
- runs **two** tool calls (one per capability token)
- writes **two audit pack .zip files**
- lets you verify them offline

Run from repo root:

```bash
python demo/run_demo.py
```

Verify offline:

```bash
python lap_cli.py schema-validate demo/out/audit_pack_demo_call1.zip
python lap_verify.py audit-pack demo/out/audit_pack_demo_call1.zip

python lap_cli.py schema-validate demo/out/audit_pack_demo_call2.zip
python lap_verify.py audit-pack demo/out/audit_pack_demo_call2.zip
```

---

## What you get

### Core (PDP / governance logic)
- Evidence-based action evaluation (risk tiering)
- Decision hashing/binding (`action_id` + `evidence_hash` + `tier/outcome/reason`)
- CLI workflows

### Gateway (PEP / enforcement)
- **Capability tokens** (Ed25519-signed) bound to action + evidence + decision
- **Budgets** (calls, bytes in/out, spend, duration) enforced server-side
- **Replay resistance**
  - T2/T3: nonce tracking (DB + hotpath cache)
  - T3: monotonic counter enforcement
- **Identity + session binding** for T2/T3 (fail-closed)
  - gateway-issued sessions via `POST /v1/session/new`
- **Signed receipts** for every invocation + denial receipts
- **Tamper-evident audit log** (hash-chained; fsync’d)

---

## Architecture (mental model)

```
Agent → (evaluate) → PDP → decision (+ token?)
Agent → (invoke with token) → PEP/Gateway → Tool (credentials only inside gateway)
                                     ↓
                                signed receipt + audit log
```

**Boundary warning:** “Non-bypassable” only holds if **tools/credentials/egress are actually behind the gateway**. If an agent can reach tools directly, no policy layer can stop it.

For the full statement of assumptions and attacker models, see **`THREAT_MODEL.md`**.

---

## Installation

From source (recommended while iterating):

```bash
pip install -e ".[gateway,dev]"
```

Core-only (no FastAPI gateway):

```bash
pip install -e .
```

---

## Developer quick checks

Run these three commands from repo root:

```bash
python -m compileall .
python -m pytest -q
python -m lap_schema_validate spec/test_vectors/receipt_basic.json
```

Or use the convenience script:

```bash
./scripts/dev_check.sh
```

### Supply-chain checks

CI runs a few lightweight security gates on the shipped code:

- `bandit` (static security scan)
- `pip-audit` (dependency vulnerability audit)
- CycloneDX SBOM generation (`sbom.cdx.json`)

See `SECURITY.md` for details.

---

## CLI entry points

| Command | What it does |
|---|---|
| `lap` | Core LAP CLI |
| `lap-gateway` | Start the FastAPI gateway (PEP) |
| `lap-gateway-runner` | Fail-dead runner (useful in pipelines) |
| `lap-verify` | Offline verification of audit packs / artifacts |

You can also run the full conformance suite (vectors + golden packs):

```bash
lap-conformance
```

### Interop check (test vectors)

If you're implementing LAP in another language, use the built-in deterministic test vectors:

```bash
lap-verify vectors spec/test_vectors
```

Go reference verifier (independent, dependency-free):

```bash
go run ./go/lapverify/cmd/lapverify vectors spec/test_vectors
go run ./go/lapverify/cmd/lapverify audit-pack spec/golden_packs/golden_pack_basic.zip --require-invocations
```

Validate artifacts and packs against the published JSON Schemas:

```bash
lap schema-validate spec/test_vectors/evidence_basic.json
lap schema-validate spec/golden_packs/golden_pack_basic.zip
```

See `spec/INTEROP.md` for the MUST/SHOULD compliance notes and fixture expectations.

The schemas live in `spec/schemas/`, and canonical JSON rules are documented in `spec/CANONICAL_JSON.md`.

---

## Deployment (reverse proxy baseline)

For anything exposed beyond localhost, run the gateway behind a reverse proxy (TLS termination + real rate limiting + security headers).

- See `DEPLOYMENT.md` for production guidance
- See `deploy/` for a hardened Nginx + Docker Compose baseline

## Quickstart (Gateway)

### 1) Configure signing

Generate a 32-byte seed (64 hex chars):

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Set:

```bash
export LAP_GATEWAY_SIGNING_KEY="<<64-hex-chars>>"
```

Or point the gateway at a key file containing the 64-hex seed (recommended for local dev):

```bash
export LAP_GATEWAY_SIGNING_KEY_FILE="/path/to/gateway_seed.hex"
```

⚠️ The gateway will **refuse to start** without a signing key configured.
For demos/tests only, you can allow an ephemeral key via:

```bash
export LAP_ALLOW_EPHEMERAL_SIGNING_KEYS=1
```

For a stronger boundary, use an external signer:
- `LAP_GATEWAY_SIGNING_CMD`
- `LAP_GATEWAY_PUBLIC_KEY_HEX`
- `LAP_GATEWAY_SIGNING_CMD_TIMEOUT_SECONDS`

#### Key rotation (optional)

If you want to rotate gateway signing keys without breaking verification for older audit packs/tokens,
configure a **keyset** instead of a single key:

```bash
export LAP_GATEWAY_KEYSET_JSON='{
  "active_kid": "gw_2026_01",
  "keys": {
    "gw_2026_01": {"seed_hex": "<64-hex-seed>"},
    "gw_2025_12": {"public_key_hex": "<64-hex-pubkey>"}
  }
}'
```

- The gateway will **sign** new tokens/receipts with `active_kid`.
- The gateway will **accept** tokens signed by *any* gateway key in the keyset (useful for grace periods).
- Verifiers use `trusted_keys.json` (a keyset) to select the correct key by `key_id`.

You can also place the JSON in a file and set `LAP_GATEWAY_KEYSET_FILE=/path/to/keyset.json`.

### 2) Configure caller authentication (recommended)

```bash
export LAP_API_KEYS_JSON='{"dev-key-1":"agent_001"}'
```

### 2b) Configure trusted reviewer keys (for T3 external approvals)

External approvals (T3) are verified using **trusted reviewer public keys**.
Provide them as a JSON object:

```bash
export LAP_TRUSTED_REVIEWER_KEYS_JSON='{"reviewer_1":"<public_key_hex>","reviewer_2":"<public_key_hex>"}'
```

Or load from a file:

```bash
export LAP_TRUSTED_REVIEWER_KEYS_FILE="/path/to/reviewer_keys.json"
```

### 2c) Optional: tool allowlists by tier

By default, the gateway uses conservative allowlists for T2/T3. You can override them:

```bash
export LAP_ALLOWED_TOOLS_BY_TIER_JSON='{"T2_HIGH_STAKES":["mock"],"T3_CATASTROPHIC":["mock"]}'
```

### 2d) Optional: hardening knobs (recommended defaults)

Request size limit (best-effort; checks Content-Length):

```bash
export LAP_MAX_REQUEST_BYTES=1048576
```

In-process rate limits (per agent/key/IP; best-effort). Disable by setting `0`:

```bash
export LAP_RATE_LIMIT_SESSION_NEW="30/m"
export LAP_RATE_LIMIT_MINT_T3="60/m"
export LAP_RATE_LIMIT_EXTERNAL_APPROVAL="60/m"
export LAP_RATE_LIMIT_MAX_KEYS=20000
```

Session issuance bounds and caps:

```bash
export LAP_SESSION_TTL_MIN_SECONDS=60
export LAP_SESSION_TTL_MAX_SECONDS=86400
export LAP_MAX_ACTIVE_SESSIONS_PER_AGENT=10
export LAP_MAX_ACTIVE_SESSIONS_GLOBAL=10000
```

### 3) Start the server

```bash
lap-gateway --host 127.0.0.1 --port 8000
```

Health check:

```bash
curl http://127.0.0.1:8000/v1/health
```

### 4) Create a gateway-issued session (required for T2/T3)

```bash
curl -s -X POST "http://127.0.0.1:8000/v1/session/new" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: dev-key-1" \
  -d '{"ttl_seconds": 3600}'
```

---

## Boundary demo (docker-compose)

See **`demo/`** for a reference Docker Compose setup that demonstrates a **non-bypassable boundary**:
- the tool is only reachable from the gateway network
- the agent cannot directly reach the tool
- tool credentials live only in the gateway

---

## Standardization & contributing

- `STANDARDIZATION_NOTES.md` — what to standardize (hashing, token/receipt contracts)
- `CONTRIBUTING.md` — how to help (tests, docs, bypass reviews)
- `SECURITY.md` — how to report vulnerabilities responsibly

---



## For auditors / reviewers

If you are reviewing LAP for security, compliance, or protocol soundness, start here:

- **CLAIMS.md** — what LAP guarantees and does not guarantee (boundary assumptions).
- **THREAT_MODEL.md** — threat model and attacker capabilities.
- **SECURITY_REVIEW.md** — reviewer-oriented architecture, attack surfaces, and reproduction steps.
- **CLAIMS_TESTS_MAP.md** — mapping from security claims to concrete tests/scripts.

## Repo layout

- `lattice_audit_v1_7.py` — core protocol logic (PDP)
- `lap_cli.py` — CLI + config wiring for PDP
- `lap_gateway/` — FastAPI gateway (PEP), tokens, receipts, replay, auth, lockdown
- `lap_verify.py` — offline verifier for audit packs/artifacts
- `tests/` — unit tests

---


## Observability

The gateway can expose Prometheus metrics at `GET /metrics` (optional). A minimal Prometheus + Grafana stack and starter dashboard live under `deploy/observability/`.

### Enable metrics
Metrics are enabled when:
- `prometheus_client` is installed (otherwise metrics are a safe no-op), and
- `LAP_METRICS_ENABLED` is not set to a falsey value.

Recommended install:
```bash
pip install -e ".[gateway]" prometheus-client
```

### Protect /metrics
Environment variables:
- `LAP_METRICS_ENABLED` (default: `1`)
- `LAP_METRICS_TOKEN` (optional): if set, `/metrics` requires either
  - `Authorization: Bearer <token>` or
  - `X-Metrics-Token: <token>`
- `LAP_METRICS_REQUIRE_AUTH` (optional): if true and API auth is enabled, `/metrics` requires a valid `X-Api-Key`.

### Compose
Bring up the production stack + observability overlay:

```bash
docker compose   -f deploy/docker-compose.production.yml   -f deploy/observability/docker-compose.observability.yml   up --build
```

Grafana defaults to `admin / admin` on `http://localhost:3000`.



### Operational stats (`/v1/stats`)
The gateway also exposes a lightweight JSON stats endpoint at `GET /v1/stats` (in-memory counters; resets on restart).
This is useful for basic ops checks when Prometheus is not installed.

Environment variables:
- `LAP_STATS_REQUIRE_AUTH` (default: `0`)
- `LAP_STATS_TOKEN` (optional): if set and auth is required, `/v1/stats` accepts either:
  - `Authorization: Bearer <token>`
  - `X-Stats-Token: <token>`

### Runbooks
Operator playbooks live in `runbooks/`:
- `runbooks/INCIDENT_RESPONSE.md`
- `runbooks/KEY_ROTATION.md`
- `runbooks/OUTAGE_PLAYBOOKS.md`


## Complete mediation adapters

For agent integrations, see `lap_gateway/adapters.py` (HTTP client + router patterns) and `demo/`.

## License

MIT (see `LICENSE`).
---

## Deployment

For a hardened reverse-proxy baseline (TLS + rate limits + health checks), see:

- `DEPLOYMENT.md`
- `deploy/` (Docker Compose + Nginx config)