# Golden Audit Packs

These are deterministic fixtures intended for offline verification and interop tests.

## Files

- `golden_pack_basic.zip`
  - Approved action
  - Includes a capability token + a signed tool invocation receipt
  - Includes `invocations.json` so verifiers can check params/result/response hash commitments

- `golden_pack_spliced.zip`
  - Same as `golden_pack_basic.zip`, but `invocations.json` has been modified to simulate a splice/mix-and-match attack.
  - Should fail verification with `PARAMS_HASH_MISMATCH`.

## Verify

```bash
# hash + signature verification
lap-verify audit-pack spec/golden_packs/golden_pack_basic.zip

# expect failure (splice)
lap-verify audit-pack spec/golden_packs/golden_pack_spliced.zip

# JSON schema validation
lap schema-validate spec/golden_packs/golden_pack_basic.zip
```
