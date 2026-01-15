# Observability Pack (Prometheus + Grafana)

This folder provides a minimal, dependency-light observability stack for LAP Gateway.

## Quick start (compose)
From repo root:

```bash
docker compose \
  -f deploy/docker-compose.production.yml \
  -f deploy/observability/docker-compose.observability.yml \
  up --build
```

Then:
- Grafana: http://localhost:3000  (admin / admin)
- Prometheus: http://localhost:9090  (inside compose network)

## Metrics endpoint
The gateway exposes `GET /metrics` when `prometheus_client` is installed.

Environment variables:
- `LAP_METRICS_ENABLED` (default: 1)
- `LAP_METRICS_TOKEN` (optional): if set, /metrics requires
  - `Authorization: Bearer <token>` or `X-Metrics-Token: <token>`
- `LAP_METRICS_REQUIRE_AUTH` (default: off unless set): if true and API auth is enabled,
  /metrics requires a valid `X-Api-Key`.

Recommended for production:
- Put `/metrics` behind the reverse proxy or make it internal-only.
- Use `LAP_METRICS_TOKEN` and configure the scraper accordingly.
