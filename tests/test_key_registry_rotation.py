import json
from pathlib import Path


def test_key_registry_rotation_revocation_and_unknown(tmp_path: Path):
    from lap_gateway.crypto import Ed25519KeyPair, TrustedKeyStore
    from lap_schema_validate import validate_file

    old_k = Ed25519KeyPair.generate("old")
    new_k = Ed25519KeyPair.generate("new")

    registry = {
        "old": {
            "public_key_hex": old_k.public_key_hex,
            "status": "active",
            "not_before_utc": "2026-01-01T00:00:00+00:00",
            "not_after_utc": "2026-01-10T00:00:00+00:00",
        },
        "new": {
            "public_key_hex": new_k.public_key_hex,
            "status": "active",
            "not_before_utc": "2026-01-10T00:00:00+00:00",
            "not_after_utc": "2026-02-01T00:00:00+00:00",
        },
        "rev": {
            "public_key_hex": old_k.public_key_hex,
            "status": "revoked",
        },
    }

    # Schema validation for registry format (strict fields).
    reg_path = tmp_path / "key_registry.json"
    reg_path.write_text(json.dumps(registry, indent=2), encoding="utf-8")
    ok, msgs = validate_file(reg_path)
    assert ok, [m.detail for m in msgs if not m.ok]

    store = TrustedKeyStore.from_config(registry)

    msg = b"hello-world"
    sig_old = old_k.sign(msg)
    sig_new = new_k.sign(msg)

    # Rotation: old key valid for old artifacts (signed within its window)
    assert store.verify_signature("old", msg, sig_old, signed_at_utc="2026-01-05T00:00:00+00:00") is True
    # But old key invalid for new artifacts (outside its not_after)
    assert store.verify_signature("old", msg, sig_old, signed_at_utc="2026-01-15T00:00:00+00:00") is False

    # New key valid for new artifacts
    assert store.verify_signature("new", msg, sig_new, signed_at_utc="2026-01-15T00:00:00+00:00") is True
    # New key invalid before its not_before
    assert store.verify_signature("new", msg, sig_new, signed_at_utc="2026-01-05T00:00:00+00:00") is False

    # Revocation always fails
    assert store.verify_signature("rev", msg, sig_old, signed_at_utc="2026-01-05T00:00:00+00:00") is False

    # Unknown key_id fails closed
    assert store.verify_signature("unknown", msg, sig_old, signed_at_utc="2026-01-05T00:00:00+00:00") is False

    # Legacy mode allows window violations (but still fails revoked/unknown)
    assert store.verify_signature("old", msg, sig_old, signed_at_utc="2026-01-15T00:00:00+00:00", legacy_verify=True) is True
    assert store.verify_signature("rev", msg, sig_old, legacy_verify=True) is False
    assert store.verify_signature("unknown", msg, sig_old, legacy_verify=True) is False
