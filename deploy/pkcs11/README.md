# Hard-key mode (PKCS#11 / HSM) reference

This folder provides a **reference deployment pattern** for running LAP in **hard-key mode** by moving signing
out of the gateway process and into an **external signer** backed by a non-exportable key (HSM/TPM/SmartCard/Enclave).

LAP’s gateway supports this via:

- `SIGNER_MODE=external`
- `SIGNER_CMD=/path/to/signer-wrapper ...`

The external signer receives the message bytes on **stdin** and must return a signature on **stdout**
(base64 by default in the examples here).

> Note: Ed25519 (EdDSA) support via PKCS#11 varies by vendor/module. This reference shows a pattern using
> `pkcs11-tool` where available. If your module doesn’t support Ed25519 signing, use the same pattern with
> your vendor’s signing CLI/SDK or a remote signing service (still non-exportable keys).

---

## Threat model benefit

Moving signing out of the gateway reduces risk from:

- gateway host compromise
- container escape within the gateway runtime
- accidental key leakage via logs/core dumps

In hard-key mode, the gateway **never holds private key material**. It only holds:

- the signer command path
- the signer **key_id**
- the corresponding public key (for receipts/attestations verification)

---

## Quick start (template)

### 1) Choose a PKCS#11 provider

Examples:
- SoftHSM2 (dev only)
- CloudHSM / Nitro Enclaves KMS proxy / vendor HSM
- Smart cards / tokens with PKCS#11 (check Ed25519 support)

Install tooling (Linux):
- `pkcs11-tool` (usually from `opensc`)
- your vendor’s PKCS#11 module (`.so`)

### 2) Configure the external signer wrapper

Copy `.env.pkcs11.example` and edit the module path, slot, and key label/id.

The wrapper scripts provided:
- `pkcs11_signer.sh` – shell wrapper around `pkcs11-tool`
- `pkcs11_signer.py` – convenience wrapper (still shells out to pkcs11-tool)

Both:
- read message bytes from stdin
- write base64 signature to stdout

### 3) Configure LAP to use the external signer

Example environment variables:

```bash
export SIGNER_MODE=external
export SIGNER_CMD="deploy/pkcs11/pkcs11_signer.py --module /usr/lib/your_pkcs11.so --slot 0 --key-id 01"
export SIGNER_OUTPUT=base64
export SIGNER_TIMEOUT_MS=1500
```

Also ensure the gateway knows the public key for `key_id` in your trusted key registry
(e.g., `trusted_keys.json`).

### 4) Run the gateway

Run normally (docker-compose or k8s). In production, run the signer in a **separate trust domain**:
- separate container/VM
- minimal filesystem access
- no outbound network except what’s required
- strict allowlist of gateway → signer communication (or local unix socket)

---

## Operational notes

### Latency
Typical expected signing latency:
- local HSM/daemon: ~2–20ms
- network remote signer: ~10–150ms (depends heavily on transport & load)

### Fail-closed behavior
If the signer is unavailable or times out:
- LAP denies execution (no tool call)
- reason: `SIGNER_UNAVAILABLE`

This prevents the “tool executed but receipt unsigned” failure mode.

---

## Systemd example (optional)

See `signer.service` for a minimal pattern to run the signer wrapper as a service.
You may prefer a containerized service instead.

---

## Troubleshooting

- If you see “mechanism not supported”: your PKCS#11 module may not support Ed25519/EdDSA.
  Use vendor tooling or a remote signer service that can produce Ed25519 signatures.
- If signatures verify locally but not elsewhere: ensure everyone uses the same key_id and public key bytes.
