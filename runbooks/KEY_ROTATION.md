# Key Rotation (LAP Gateway)

Rotating keys is a security and operational procedure. Do it deliberately and record the change.

## Keys involved
- Gateway signing key (receipts/tokens/attestations)
- Reviewer keys (external approvals, if used)
- Transparency/anchoring keys (if applicable)

## Rotation strategy
- Add new public key to trusted set first.
- Deploy new signing key next.
- Remove old trusted key only after a deprecation window.

## Steps (gateway signing key)
1. Generate a new keypair (prefer hardware-backed or external signer).
2. Update deployment:
   - set new key location / signer command
   - restart gateway
3. Publish new public key:
   - update `LAP_TRUSTED_KEYS_JSON` (or file) for verifiers/auditors
4. Verify:
   - run a demo tool call
   - export an audit pack
   - verify offline (Python + Go)
5. Deprecate old key:
   - keep old key trusted for a window (audit continuity)
   - remove after window closes

## Notes
- Rotation should be tested in staging with the same verifier toolchain.
- Keep a log of rotation events (date/time, key ids, reason).
