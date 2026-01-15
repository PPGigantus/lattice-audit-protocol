# Deployment guide (reverse-proxy baseline)

This project is designed to run the **LAP Gateway (PEP)** behind a reverse proxy.

The reverse proxy provides:
- TLS termination (HTTPS)
- Real IP forwarding
- Centralized rate limiting / request size caps
- Security headers
- Health checks and safe defaults

## Non-bypassable checklist (required for enforcement)

If you satisfy this checklist, LAP provides **enforcement** (PEP). If you don’t, LAP degrades to **logging/telemetry**.

- **No direct tool path from agents:** Agents must not be able to reach tool endpoints (NetworkPolicy / SG / NACL / service-mesh policy).
  - If an agent can call tools directly, it can bypass the gateway and LAP becomes **logging-only**.
- **Tool credentials live only at the tool boundary:** Tool secrets must live in the tool-service (or gateway-to-tool boundary), never in agent pods.
- **Deny-by-default egress for agents:** Block “free internet” and only allow what is explicitly required.
- **Gateway is the only allowed tool caller:** In Kubernetes, enforce `gateway -> tool-service` with NetworkPolicy; in cloud, use private subnets + security groups.
- **Gateway ingress is controlled:** Put the gateway behind a reverse proxy/LB with TLS, request size caps, and rate limits.
- **Signing keys are protected & rotated:** Prefer external signer/HSM/KMS; rotate with key IDs and maintain a trusted key registry.
- **Least privilege identities:** Separate service accounts; no shared writable volumes between agent/gateway/tool.
- **Durable audit retention:** Store/export receipts/attestations/anchors for offline verification; treat logs as compliance artifacts.
- **Time assumptions are explicit:** Keep time sync and document allowed drift if you use validity windows.

## Quick start (Docker Compose + Nginx TLS)

A hardened baseline lives in `deploy/docker-compose.reverse-proxy.yml`.

### 1) Create an `.env`
Copy and edit:

```bash
cp deploy/.env.example .env
```

At minimum you must set **either**:
- `LAP_GATEWAY_SIGNING_KEY` (64 hex chars)
  - or `LAP_GATEWAY_SIGNING_KEY_FILE`
  - or a keyset: `LAP_GATEWAY_KEYSET_JSON` / `LAP_GATEWAY_KEYSET_FILE`

And also:
- `LAP_API_KEYS_JSON` or `LAP_API_KEYS_FILE`

> By default the gateway **refuses to start** without a signing key unless `LAP_ALLOW_EPHEMERAL_SIGNING_KEYS=1`.

### 2) Provide TLS certs
For local testing you can generate a self-signed cert:

```bash
bash deploy/scripts/generate_self_signed_cert.sh \
  --cn localhost \
  --out deploy/certs
```

For production, mount real certs (e.g., Let’s Encrypt) into `deploy/certs/`:
- `fullchain.pem`
- `privkey.pem`

### 3) Start

```bash
docker compose -f deploy/docker-compose.reverse-proxy.yml up --build
```

- Nginx listens on **443** (HTTPS)
- Gateway is private on `gateway_net` and not exposed directly

### 4) Health checks
- `https://<host>/v1/health`

## Recommended production pattern

1) **Network isolation**
- Gateway on an internal network
- Tools on a private tool network
- Agent cannot reach tool network directly

2) **Strong identity**
- Enable API-key auth at minimum.
- For serious deployments, use mTLS or OIDC upstream and map identities to `X-Agent-Id` at the proxy.

3) **External signing boundary (strong mode)**
- Prefer `LAP_GATEWAY_SIGNING_CMD` + external signer for non-forgeability under host compromise.

4) **Rate limits**
- Keep Nginx limits on:
  - `/v1/session/new`
  - `/v1/mint-t3-token`
  - `/v1/external-approval`

5) **Logs**
- Ship Nginx + gateway logs to centralized logging.
- Store audit logs on durable storage.

## Reverse-proxy notes

### Real IPs
If you are behind a load balancer, configure it to pass `X-Forwarded-For` and ensure Nginx is the only component exposed to the public internet.

### Uvicorn proxy headers
If you want uvicorn/FastAPI to trust `X-Forwarded-*`, start the gateway with:

```bash
lap-gateway --proxy-headers --forwarded-allow-ips "*"
```

Or set environment variables (see `.env.example`).


## Production-shaped baseline

A more production-shaped compose file is included at:

- `deploy/docker-compose.production.yml`

It includes an internal-only tool network and an optional agent container on an `internal: true` network (no internet egress).

See:
- `deploy/PRODUCTION_GUIDE.md`
- `deploy/cloud/README.md`

## Hard-key mode via external signer (recommended for production)

By default, the gateway can sign receipts/tokens/attestations using an in-process Ed25519 key (good for demos/tests).
For production, you should strongly prefer a **non-exportable key boundary** (TPM/HSM/enclave/remote signer), so the
gateway process **never holds private key material**.

### Option A: Force external signer via env (portable seam)

Set:

- `SIGNER_MODE=external`
- `SIGNER_CMD="<command to run>"`
- (optional) `SIGNER_TIMEOUT_SECONDS=2.0`

The command contract is:

- stdin: `base64(message)` (plus optional trailing newline)
- stdout: `base64(signature)`

Example (development-style external signer process):

```bash
export SIGNER_MODE=external
export SIGNER_CMD="python -m my_signer_daemon"
```

### Option B: Configure an external signer in the gateway keyset

If you use `LAP_GATEWAY_KEYSET_JSON` / `LAP_GATEWAY_KEYSET_FILE`, you can set the active key entry to include a
`signing_cmd` (and optional `timeout_seconds`) alongside the pinned public key. The gateway will sign via the command
but verify using the pinned public key.

### Fail-closed guarantee

If the external signer errors or times out, the gateway will **fail closed**: it will not mint tokens or receipts.


## Hard-key mode reference (PKCS#11 / HSM)

For a concrete hard-key deployment pattern using the existing external-signer seam, see `deploy/pkcs11/README.md`.
This provides wrapper scripts and configuration templates for moving signing into a non-exportable key boundary.
