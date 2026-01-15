# LAP Interoperability Test Vectors

These files let independent implementations validate they match LAP's hashing and signature rules.

## What's included

- `evidence_basic.json` — Evidence object
- `decision_basic.json` — Decision object
- `params_basic.json` — Example tool params
- `token_basic.json` — Deterministic signed capability token
- `token_revoked_effective_later.json` — Deterministic signed token that must verify **with a lifecycle warning** when the key is revoked effective at a later date
- `receipt_basic.json` — Deterministic signed receipt
- `vectors.json` — Manifest of cases + expected outputs

## Verifying

From repo root:

```bash
python -m pip install -e ".[gateway]"
lap-verify vectors spec/test_vectors
```

## Regenerating

The expected values are generated (not hand-edited):

```bash
python scripts/generate_test_vectors.py
```

If you change canonicalization/hashing/signature payload rules, you must regenerate vectors and bump the vectors version.
