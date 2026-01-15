
import json
from pathlib import Path


def test_time_bounded_revocation_trust_at_event_time(tmp_path: Path):
    from lap_gateway.crypto import Ed25519KeyPair, TrustedKeyStore
    from lap_schema_validate import validate_file

    k = Ed25519KeyPair.generate("k1")
    msg = b"hello"
    sig = k.sign(msg)

    # Time-bounded revocation inside registry entry.
    registry = {
        "k1": {
            "public_key_hex": k.public_key_hex,
            "status": "active",
            "revoked_at_utc": "2026-01-10T00:00:00+00:00",
            "revoked_reason": "compromise suspected",
        }
    }

    reg_path = tmp_path / "key_registry.json"
    reg_path.write_text(json.dumps(registry, indent=2), encoding="utf-8")
    ok, msgs = validate_file(reg_path)
    assert ok, [m.detail for m in msgs if not m.ok]

    store = TrustedKeyStore.from_config(registry)

    # Before effective revocation: verifies, but with warning in detailed API.
    ok_bool = store.verify_signature("k1", msg, sig, signed_at_utc="2026-01-05T00:00:00+00:00")
    assert ok_bool is True
    ok_det, info = store.verify_signature_detailed("k1", msg, sig, signed_at_utc="2026-01-05T00:00:00+00:00")
    assert ok_det is True
    assert info.get("warning") == "key_revoked_effective_later"
    assert "revoked_at_utc" in info

    # At/after effective revocation: fails closed.
    assert store.verify_signature("k1", msg, sig, signed_at_utc="2026-01-10T00:00:00+00:00") is False
    assert store.verify_signature("k1", msg, sig, signed_at_utc="2026-01-15T00:00:00+00:00") is False


def test_wrapped_revocation_registry_applies(tmp_path: Path):
    from lap_gateway.crypto import Ed25519KeyPair, TrustedKeyStore
    from lap_schema_validate import validate_file

    k = Ed25519KeyPair.generate("kid")
    msg = b"wrapped"
    sig = k.sign(msg)

    wrapped = {
        "version": 1,
        "keys": {
            "kid": {
                "public_key_hex": k.public_key_hex,
                "status": "active",
            }
        },
        "revocations": [
            {"key_id": "kid", "revoked_at_utc": "2026-02-01T00:00:00+00:00", "reason": "rotated"},
        ],
    }

    p = tmp_path / "trusted_keys.json"
    p.write_text(json.dumps(wrapped, indent=2), encoding="utf-8")
    ok, msgs = validate_file(p)
    assert ok, [m.detail for m in msgs if not m.ok]

    store = TrustedKeyStore.from_config(wrapped)

    ok_det, info = store.verify_signature_detailed("kid", msg, sig, signed_at_utc="2026-01-20T00:00:00+00:00")
    assert ok_det is True
    assert info.get("warning") == "key_revoked_effective_later"

    assert store.verify_signature("kid", msg, sig, signed_at_utc="2026-02-02T00:00:00+00:00") is False
