# Security Policy

## Reporting a vulnerability

If you believe you found a security issue (bypass path, signature weakness, replay hole, etc.), please **do not** open a public GitHub issue.

Preferred process:

1. Open a **private** disclosure with maintainers (GitHub Security Advisories), or contact the maintainer directly.
2. Include:
   - a clear description of the issue
   - minimal PoC steps
   - affected files/lines
   - impact (what invariant is broken?)
3. If possible, include a suggested fix or mitigation.

## Supported versions

Only the most recent tagged release is considered supported for security fixes.

## Design assumptions

LAP is an enforcement/auditability layer. It does **not** claim to solve inner alignment.

The most important security assumption is the **boundary**:

- the gateway/PEP must be deployed such that the agent cannot directly reach tool credentials or privileged tool endpoints.

See `THREAT_MODEL.md` and `demo/` for boundary examples.

## External signer seam (hard-key boundary)

LAP supports delegating signing to an external command so the gateway process never holds private key material.

Enable:

- `SIGNER_MODE=external`
- `SIGNER_CMD="..."`
- optional `SIGNER_TIMEOUT_SECONDS`

This is intended to connect to TPM/HSM/enclave signers or a locked-down signing daemon.
If the signer is unavailable or errors, LAP fails closed (no signed receipt/token is issued).


## Hard-key deployments

LAP supports moving signing out of the gateway process via `SIGNER_MODE=external`. For a PKCS#11/HSM reference pattern, see `deploy/pkcs11/README.md`.

## Supply-chain posture

This repository ships with CI security gates intended to catch common supply-chain and code-hygiene issues:

- **Dependency audit:** `pip-audit` runs in CI on the resolved environment.
- **Static security scan:** `bandit` runs in CI on shipped Python code paths.
- **SBOM generation:** CI generates a CycloneDX SBOM (`sbom.cdx.json`) and uploads it as a build artifact.

These checks do not replace an independent security review, but they help prevent regressions.


## Operational runbooks

See `runbooks/` for incident response, key rotation, and outage playbooks.
