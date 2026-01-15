# Production deployment guide

This guide documents a **production-shaped** baseline for LAP:

- Gateway (PEP) is **not exposed** directly to the public internet.
- All inbound traffic terminates at a reverse proxy (TLS + limits + headers).
- Tools live on a **private network** reachable only from the gateway.
- Optional “agent” container runs with **no internet egress** (internal network).

> **Reminder:** LAP is only “non-bypassable” if the agent cannot reach tools directly and does not hold tool credentials.

---

## What’s included

- `deploy/docker-compose.production.yml`
  - `nginx` (public edge, TLS)
  - `gateway` (private, internal networks only)
  - `tool` (private, tool network only)
  - `agent` (optional boundary test)

- Nginx config:
  - request size caps
  - rate limits per sensitive endpoint
  - security headers
  - health endpoints

---

## Required secrets / config

Create `.env` in the repo root:

```bash
cp deploy/.env.example .env
```

Minimum required for safe startup:

- `LAP_GATEWAY_SIGNING_KEY` (64 hex chars = 32-byte seed)
- `LAP_API_KEYS_JSON` or `LAP_API_KEYS_FILE`

Strongly recommended:

- `LAP_TRUSTED_REVIEWER_KEYS_JSON` or `..._FILE` (so T3 approvals can work)
- `LAP_ALLOW_EPHEMERAL_SIGNING_KEYS=0` (default in production compose)

---

## Bring up the stack

1) Generate local certs (dev/staging):

```bash
bash deploy/scripts/generate_self_signed_cert.sh --cn localhost --out deploy/certs
```

2) Start:

```bash
docker compose -f deploy/docker-compose.production.yml up --build
```

3) Verify:

```bash
curl -k https://localhost/v1/health
```

---

## Boundary check (recommended)

The `agent` service exists to sanity-check the boundary:

- It can reach `nginx`
- It cannot reach the `tool` container directly (not on `tool_net`)
- It has no public internet egress (only on `agent_net`, which is `internal: true`)

To run just the agent check:

```bash
docker compose -f deploy/docker-compose.production.yml run --rm agent
```

---

## Hardening checklist

- Put the stack behind a cloud LB/WAF if internet-exposed.
- Restrict inbound firewall rules to the reverse proxy only.
- Mount secrets via a secret manager (not plaintext `.env`) in real deployments.
- Use an **external/hardware-backed signer** for the gateway signing key if you need strong non-forgeability.
- Enable structured logging and ship audit logs off-host.

See `deploy/cloud/README.md` for cloud load balancer and WAF guidance.
