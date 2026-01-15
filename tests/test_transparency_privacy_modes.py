from lap_gateway.transparency import apply_privacy_mode


def test_privacy_mode_hash_only_strips_fields():
    entry = {
        "timestamp_utc": "2026-01-14T00:00:00Z",
        "artifact_type": "receipt",
        "artifact_hash": "a"*64,
        "key_id": "k1",
        "signature": "sig",
        "gateway_id": "gw",
    }
    out = apply_privacy_mode(entry, "hash-only")
    assert set(out.keys()) == {"timestamp_utc", "artifact_type", "artifact_hash"}
    assert out["artifact_hash"] == "a"*64


def test_privacy_mode_metadata_preserves_fields():
    entry = {
        "timestamp_utc": "2026-01-14T00:00:00Z",
        "artifact_type": "receipt",
        "artifact_hash": "a"*64,
        "key_id": "k1",
        "signature": "sig",
        "gateway_id": "gw",
    }
    out = apply_privacy_mode(entry, "metadata")
    assert out["key_id"] == "k1"
    assert out["gateway_id"] == "gw"
