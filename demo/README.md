# LAP Boundary Demo (Docker Compose)

This demo shows the **deployment boundary** LAP assumes:

- the **tool** is **not exposed to the host** and is only reachable on a private Docker network
- the **gateway** is the only component that can reach the tool network
- an **agent** can reach the gateway, but **cannot reach the tool directly**
- tool credentials live in the gateway, not the agent

## Prerequisites

- Docker + Docker Compose

## Run

From the repo root:

```bash
docker compose -f demo/docker-compose.yml up --build
```

Gateway will be on:

- http://127.0.0.1:8000

Tool is **not exposed** to the host.

## Smoke test

Health:

```bash
curl http://127.0.0.1:8000/v1/health
```

Create a session (required for T2/T3). The demo API-key map includes `dev-key-1 → agent_001`:

```bash
curl -s -X POST "http://127.0.0.1:8000/v1/session/new" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: dev-key-1" \
  -d '{"ttl_seconds": 3600}'
```

(Optional) Try reaching the tool from the agent container (should fail):

```bash
docker exec -it lap-demo-agent sh
curl -v http://lap-tool:9000/invoke
```

The gateway *can* reach the tool (and will forward requests to it) via the `http` tool connector.

## Notes

- This demo registers an **HTTP-backed tool** by setting `LAP_HTTP_TOOL_URL`.
- The tool requires a header `X-Tool-Api-Key`, configured via `LAP_HTTP_TOOL_API_KEY`.
