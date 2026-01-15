# Reverse-proxy baseline

This folder contains a production-oriented baseline deployment:
- Nginx (TLS termination + rate limits + security headers)
- LAP Gateway (private, not directly exposed)

## Steps

1) Create `.env` in the repo root:

```bash
cp deploy/.env.example .env
```

2) Create TLS certs:

```bash
bash deploy/scripts/generate_self_signed_cert.sh --cn localhost --out deploy/certs
```

3) Start:

```bash
docker compose -f deploy/docker-compose.reverse-proxy.yml up --build
```

4) Verify:

- `https://localhost/v1/health`

> For production, replace self-signed certs with real certs, and consider placing Nginx behind a cloud load balancer/WAF.


## Production compose

A more production-shaped compose file is provided:

- `docker-compose.production.yml` (includes tool + optional agent on an internal network)

See `PRODUCTION_GUIDE.md`.


## Observability (Prometheus + Grafana)

See `deploy/observability/README.md` for a minimal Prometheus + Grafana stack and a starter dashboard.


### Hard-key signing

See `pkcs11/README.md` for a reference pattern to run LAP with an external signer backed by a non-exportable key boundary.
