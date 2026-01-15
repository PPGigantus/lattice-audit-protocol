# Outage Playbooks (Signer, PDP, Storage)

## Signer outage
**Symptom:** `SIGNER_UNAVAILABLE` errors; receipts/tokens cannot be signed.

**Expected behavior:** fail closed before tool execution.

Actions:
- Confirm signer health (daemon/PKCS11/HSM/external command).
- If using external signer command, test it directly (probe sign).
- Restore signer; then run a smoke tool call and verify pack offline.

## PDP outage / timeout
**Symptom:** `PDP_ERROR` in evaluation; evaluations deny.

**Expected behavior:** deny with `PDP_ERROR` reason.

Actions:
- Check PDP endpoint/latency
- Revert to builtin PDP mode if necessary (if allowed)
- Restore PDP; rerun evaluation and verify pack

## Storage degradation / lockdown
**Symptom:** `LOCKDOWN_ACTIVE` appears; tool results may be withheld.

**Expected behavior:** deny or withhold results and issue receipts indicating lockdown.

Actions:
- Check sqlite WAL contention / disk / latency thresholds
- Increase storage capacity / move to managed DB
- Keep lockdown until DB is healthy; then clear after window
