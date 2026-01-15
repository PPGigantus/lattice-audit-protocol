# LAP Stable Error Codes (v0.1)

This document defines stable, machine-readable error codes for LAP Core.

Goals:
- Clients can branch on `code` without parsing strings.
- Transports can use `retryable` to decide idempotent retry behavior.
- Humans still get a readable `message`.

## Error envelope

When an error is returned over HTTP (or serialized into an audit artifact),
it SHOULD follow this shape:

```json
{
  "code": "LAP_E_…",
  "message": "human-readable summary",
  "retryable": false,
  "http_status": 400,
  "details": { "optional": "structured fields" }
}
```

## Canonicalization / hashing

- `LAP_E_CANON_NON_JSON` — non-JSON-serializable type encountered
- `LAP_E_CANON_DEPTH` — max nesting depth exceeded
- `LAP_E_CANON_NONFINITE` — NaN/Infinity encountered
- `LAP_E_CANON_KEY_TYPE` — dict key is not a string
- `LAP_E_CANON_KEY_COLLISION` — unicode normalization collapses distinct keys
- `LAP_E_CANON_INT_TOO_LARGE` — integer digit length exceeds configured maximum

## Gateway / request binding

- `LAP_E_AUTH_REQUIRED` — authentication required / missing
- `LAP_E_AGENT_ID_REQUIRED` — agent identity required
- `LAP_E_SESSION_MISMATCH` — session binding mismatch
- `LAP_E_RATE_LIMITED` — request was rate limited (retryable)
- `LAP_E_LOCKDOWN_ACTIVE` — gateway lockdown active / degraded mode (retryable)
- `LAP_E_TOOL_NAME_MISMATCH` — tool_name mismatch in request

## Generic

- `LAP_E_BAD_REQUEST` — request invalid for other reasons
- `LAP_E_INTERNAL` — unexpected internal failure (retryable by default at transport)

## Witness / transparency

Witness clients use a small result taxonomy:

- ok
- duplicate (idempotent success)
- retryable_http
- permanent_http
- network_error

When surfaced as LAP error codes:

- `LAP_E_WITNESS_DUPLICATE`
- `LAP_E_WITNESS_RETRYABLE_HTTP`
- `LAP_E_WITNESS_PERMANENT_HTTP`
- `LAP_E_WITNESS_NETWORK`
