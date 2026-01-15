# LAP Canonical JSON

LAP uses canonical JSON serialization for **hash commitments** (evidence hashes, params/result hashes, etc.).

LAP currently defines **two** canonicalization profiles:

- **v1 (legacy, permissive)**: stringifies unknown types (`default=str`).
- **v2 (strict, recommended)**: strict JSON only; unknown types are an error.

Both versions use the same stable ordering and whitespace rules.

---

## v1 (legacy, permissive)

**Rules (v1):**

1. Serialize as JSON with:
   - `sort_keys=True`
   - `separators=(",", ":")` (no insignificant whitespace)
   - `ensure_ascii=False`
2. If an object contains values that are not JSON-serializable, v1 **stringifies** them using `default=str`.

**Why v1 exists:** early artifacts may include datetimes/Decimals/other types. v1 keeps hashing/signing deterministic without crashing.

Implemented by:
- `lap_gateway.crypto.canonical_json_dumps(..., version="v1")`
- `lap_gateway.crypto.canonical_json_dumps_v1(...)`

---

## v2 (strict, recommended)

**Rules (v2):**

1. Serialize as JSON with:
   - `sort_keys=True`
   - `separators=(",", ":")`
   - `ensure_ascii=False`
   - `allow_nan=False` (reject NaN/Infinity/-Infinity)
2. If an object contains values that are not JSON-serializable, v2 **MUST raise** an error (no fallback/stringification).

### Non-finite floats

v2 rejects NaN/Infinity/-Infinity (non-standard JSON) so hashes and signatures are reproducible
across language implementations (for example, Go's `encoding/json` does not permit these values).

**Why v2 is recommended:** it prevents accidental hashing of unintended representations (e.g., a datetime string that differs across locales), and makes cross-language interop cleaner.

Implemented by:
- `lap_gateway.crypto.canonical_json_dumps(..., version="v2")`
- `lap_gateway.crypto.canonical_json_dumps_v2(...)`

---

## Hashing

All hash commitments use **SHA-256** over UTF-8 bytes of the canonical JSON string:

`sha256_hex(canonical_json_dumps(obj, version=V).encode("utf-8"))`

---

## Interop: how verifiers should handle v1 and v2

Verifiers SHOULD support both versions during a transition period.

Recommended approaches:

1. **Explicit field**: include a field such as `canonical_json_version` in a manifest or envelope (e.g., audit pack `manifest.json`).
2. **Pack-level setting**: for audit packs, a single `manifest.json` setting is preferred so all commitments in the pack use the same version.

If no version is specified, verifiers SHOULD default to **v1** for backwards compatibility.

Use the test vectors in `spec/test_vectors/` to validate your implementation for both v1 and v2.
