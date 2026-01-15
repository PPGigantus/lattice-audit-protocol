# Cloud load balancer + WAF notes

This repo ships a Docker Compose reverse-proxy baseline using Nginx.
In production cloud environments you typically deploy one of:

1) **Managed LB/WAF → Nginx → Gateway** (recommended if you want proxy-level controls in-app)
2) **Managed LB/WAF → Gateway directly** (acceptable if LB/WAF provides rate limits, request size caps, and TLS)

---

## Option 1: Managed LB/WAF in front of Nginx

**Traffic flow**

Client → Cloud WAF/LB (TLS) → Nginx (internal) → Gateway (internal) → Tools (internal)

**Why this is nice**
- You keep “edge” protections at the provider (WAF signatures, bot mitigation)
- You still keep Nginx controls + consistent behavior across environments

**Must-do settings**
- Ensure the LB sets `X-Forwarded-For`, `X-Forwarded-Proto`.
- Run the gateway with:
  - `LAP_PROXY_HEADERS=1`
  - `LAP_FORWARDED_ALLOW_IPS=<LB CIDR or nginx>`
- If the LB terminates TLS, set `X-Forwarded-Proto=https` and enforce HTTPS at the edge.

---

## Option 2: Managed LB/WAF straight to Gateway

If you skip Nginx, you must replicate its protections at the LB/WAF:

- Request size caps (e.g., 1MB)
- Rate limiting for:
  - `/v1/session/new`
  - `/v1/mint-t3-token`
  - `/v1/external-approval`
- TLS + HSTS
- IP allowlists / firewall rules

Run the gateway with:
- `LAP_PROXY_HEADERS=1`
- `LAP_FORWARDED_ALLOW_IPS=<LB CIDRs>`

---

## WAF rules worth having

- Block unusually large JSON payloads (above your max)
- Rate limit POSTs to token minting and approvals
- Optional: geo/IP reputation rules, bot mitigation
- Allowlist trusted CI / internal IPs for admin endpoints (if you add any)

---

## Key management baseline

For real production, avoid storing gateway signing keys in plaintext environment variables:

- Prefer a secret manager (AWS Secrets Manager / GCP Secret Manager / Vault)
- Prefer an **external signer** (HSM/KMS) if you need hard non-forgeability
- Rotate API keys and signer keys with an explicit maintenance procedure

---

## Observability

- Ship audit logs off-host (object storage or log pipeline)
- Capture reverse proxy access logs + gateway structured logs
- Alert on:
  - frequent denials
  - repeated replay attempts
  - unusual session creation rates
