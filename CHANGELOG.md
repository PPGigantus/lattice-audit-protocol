# Changelog

## [1.4.1] - 2026-01-13

### Fixed
- Receipt verification edge case: `ToolInvocationReceipt.verify()` no longer references a non-existent `denied_at_utc` field.
- Offline audit-pack verifier now fails closed if `cryptography` is unavailable (hash-only verification requires an explicit flag).
- Audit pack manifest now records `canonical_json_version`; verifiers use it to hash/verify evidence consistently.
- Transparency anchoring normalizes DSSE signature ordering before hashing to avoid cross-implementation drift.
- Keyset loader now validates Ed25519 key material lengths and fails closed on invalid active keys.

### Changed
- Gateway API reports the installed LAP version (derived from package metadata).


## [1.4.0] - 2026-01-13

### Added
- Go reference verifier (`go/lapverify`) implementing:
  - Canonical JSON v1 hashing (evidence/params)
  - SafeHashEncode decision hashing
  - Ed25519 verification for tokens and receipts
  - Audit pack verification (zip/dir) and test vector runner
- Go interop tests (`go test ./...`) verifying `spec/test_vectors` and `spec/golden_packs/golden_pack_basic.zip`.
- CI now runs Go verifier in addition to Python checks.

## [1.3.0] - 2026-01-13

### Added
- Standardization docs: `spec/STABLE_CORE.md` and `spec/PROFILES.md`.
- Profile verification: `lap-verify profile <bronze|silver|gold> <path>`.
- Profile attestation schema + example attestations.
- Interop mutation tests for fail-closed verification.

### Changed
- CI now enforces Bronze profile and validates profile attestations.

## [1.2.0] - 2026-01-12

### Added
- Gateway key rotation support via keysets (`LAP_GATEWAY_KEYSET_JSON` / `LAP_GATEWAY_KEYSET_FILE`).
- `trusted_keys.json` JSON Schema validation (strict shape: key_id -> public_key_hex).

### Changed
- Gateway token verifier now accepts signatures from any gateway public key in the configured keyset (supports grace periods during rotation).
- `LAP_GATEWAY_SIGNING_KEY_ID` can set the `key_id` used in issued tokens/receipts for single-key deployments.

### Notes
- Backwards compatible: if no keyset is configured, behavior matches prior releases.

## [1.1.1] - 2026-01-12
### Added
- Interop Compliance Kit:
  - `lap schema-validate` command for validating LAP artifacts and audit packs against JSON Schemas.
  - Interop MUST/SHOULD notes (`spec/INTEROP.md`).
  - Golden audit pack fixture (`spec/golden_packs/golden_pack_basic.zip`) + generator script.
  - End-to-end audit-pack verification test vector (`audit_pack_verify`) wired into `lap-verify vectors`.
- CI now runs the interop fixtures (vectors, golden pack, and schema validation) in addition to tests/lint/type/security.

### Fixed
- `spec` audit pack `verify.py` now embeds the canonical JSON routine required for evidence hashing.
- Audit pack writer no longer redundantly writes `invocations.json` twice.

## [1.1.0] - 2026-01-12
### Added
- CI quality gates (GitHub Actions): tests, focused Ruff lint (E9/F/I), Pyright type check, Bandit scan, pip-audit.
- Pre-commit configuration for consistent local checks.
- Interop/spec artifacts:
  - JSON Schemas for evidence, decision, token, receipt, and external approvals (`spec/schemas/`).
  - Canonicalization + hashing rules documented as "LAP Canonical JSON v1".
  - Interoperability test vectors (`spec/test_vectors/`) and a verifier command (`lap-verify vectors`).

### Changed
- Evidence hashing for audit packs now uses the same canonical JSON routine across the repo (aligns builder/verifier with the published spec).

### Fixed
- Offline verifier and audit-pack builder now agree on canonical JSON for evidence hashing (previously could diverge depending on JSON formatting).

## [1.0.9] - 2026-01-12
### Added
- Optional Prometheus metrics (`/metrics`) with safe no-op fallback when `prometheus_client` is not installed.
- Observability pack: Prometheus + Grafana compose override and starter dashboard (`deploy/observability/`).

### Fixed
- Removed an incorrect rate-limit check in `/v1/session/new` that referenced the T3 mint limiter.
- Added metrics hooks for rate-limit and replay rejections (no effect unless metrics are enabled).

### Changed
- Version bump to 1.0.9.

## [1.0.6] - 2026-01-12
### Added
- Production-shaped Docker Compose (`deploy/docker-compose.production.yml`) with internal networks for boundary isolation.
- Cloud load balancer/WAF guidance (`deploy/cloud/README.md`).
- Production deployment walkthrough (`deploy/PRODUCTION_GUIDE.md`).

### Changed
- Demo tool server now listens on configurable `TOOL_PORT` (default 9000) for consistency across demo and production.
- Agent demo now includes a boundary check: direct tool access should fail.


All notable changes to this project will be documented here.

The format is loosely based on Keep a Changelog.

## [1.0.5] - 2026-01-12

### Added
- Production reverse-proxy baseline (`deploy/`) with Nginx TLS, rate limits, security headers, and health checks.
- Deployment guide (`DEPLOYMENT.md`) and `.env` template for hardened configuration.
- Reverse-proxy support flags/env vars for `lap-gateway` (`--proxy-headers`, `--forwarded-allow-ips`).

## [1.0.4] - 2026-01-12

### Security hardening
- **Signing keys are no longer derived from predictable IDs.** If no key is configured, the gateway fails to start unless `LAP_ALLOW_EPHEMERAL_SIGNING_KEYS=1` is set (demo/test only).
- Best-effort **request size limiting** via `LAP_MAX_REQUEST_BYTES` (default 1MB) using Content-Length checks.
- Best-effort **in-process rate limiting** (per agent/key/IP) for DoS-prone endpoints:
  - `/v1/session/new` via `LAP_RATE_LIMIT_SESSION_NEW` (default `30/m`)
  - `/v1/mint-t3-token` via `LAP_RATE_LIMIT_MINT_T3` (default `60/m`)
  - `/v1/external-approval` via `LAP_RATE_LIMIT_EXTERNAL_APPROVAL` (default `60/m`)
- **External approvals now require authentication** when API-key auth is enabled (prevents anonymous spam).

### Fixed
- Session issuance now enforces configurable TTL bounds and active-session caps (`LAP_SESSION_TTL_MIN_SECONDS`, `LAP_SESSION_TTL_MAX_SECONDS`, `LAP_MAX_ACTIVE_SESSIONS_PER_AGENT`, `LAP_MAX_ACTIVE_SESSIONS_GLOBAL`).
## [1.0.3] - 2026-01-12

### Added
- Gateway now loads signing key from `LAP_GATEWAY_SIGNING_KEY` / `LAP_GATEWAY_SIGNING_KEY_FILE` (instead of silently generating a fresh key every boot)
- Trusted reviewer public-key loading for external approvals via `LAP_TRUSTED_REVIEWER_KEYS_JSON` / `LAP_TRUSTED_REVIEWER_KEYS_FILE`
- Configurable tool allowlists by tier via `LAP_ALLOWED_TOOLS_BY_TIER_JSON` / `LAP_ALLOWED_TOOLS_BY_TIER_FILE`

### Fixed
- T3 minting now enforces strong auth and validates session ownership/expiry (fail-closed)
- Post-evaluation enforcement now keys off the *actual* evaluated tier (prevents tier-estimate mismatch fail-open)
- Canonical JSON hashing is now consistent for evidence and T3 parameter binding
- API-key auth mismatch detection is now consistent across `resolve_identity` and `resolve_context`

## [1.0.2] - 2026-01-12

### Added
- Standardization docs: `CONTRIBUTING.md`, `SECURITY.md`, `STANDARDIZATION_NOTES.md`
- Demo boundary scaffold in `demo/` (Docker Compose + reference HTTP tool)
- Adversarial regression tests for session issuance/validation and session binding

### Fixed
- Implemented missing gateway session store methods (`create_session`, `validate_session`, `purge_expired_sessions`)
- Implemented `_evaluate_with_lap_protocol` and gated protocol-engine enablement behind `LAP_ENABLE_PROTOCOL_ENGINE`

## [1.0.1] - 2026-01-11

- Hardened gateway logic (auth/session binding enforcement) and improved README.
