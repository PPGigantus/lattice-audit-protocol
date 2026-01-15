from pathlib import Path


def test_schema_validate_vectors_and_golden_pack():
    from lap_schema_validate import validate_path

    repo = Path(__file__).resolve().parents[1]

    ok, msgs = validate_path(repo / "spec" / "test_vectors" / "evidence_basic.json")
    assert ok, [m.detail for m in msgs if not m.ok]

    ok, msgs = validate_path(repo / "spec" / "test_vectors" / "decision_basic.json")
    assert ok, [m.detail for m in msgs if not m.ok]

    ok, msgs = validate_path(repo / "spec" / "test_vectors" / "token_basic.json")
    assert ok, [m.detail for m in msgs if not m.ok]

    ok, msgs = validate_path(repo / "spec" / "test_vectors" / "receipt_basic.json")
    assert ok, [m.detail for m in msgs if not m.ok]

    ok, msgs = validate_path(repo / "spec" / "golden_packs" / "golden_pack_basic.zip")
    assert ok, [m.detail for m in msgs if not m.ok]


def test_schema_validate_rejects_missing_required_fields(tmp_path: Path):
    from lap_schema_validate import validate_file

    # Evidence requires action_id, description, timestamp_utc, irreversibility
    bad = tmp_path / "evidence.json"
    bad.write_text('{"action_id": "X"}', encoding="utf-8")

    ok, msgs = validate_file(bad, schema_name="evidence")
    assert not ok
    assert any("required" in m.detail.lower() for m in msgs if not m.ok)
