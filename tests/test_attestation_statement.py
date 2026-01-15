import json
from pathlib import Path


def test_receipt_to_attestation_statement_validates_schema(tmp_path: Path):
    from lap_gateway.attestations import receipt_to_attestation_statement
    from lap_schema_validate import validate_file

    repo = Path(__file__).resolve().parents[1]
    receipt = json.loads((repo / "spec" / "test_vectors" / "receipt_basic.json").read_text(encoding="utf-8"))

    manifest = {
        "action_id": receipt["action_id"],
        "evidence_hash": receipt["evidence_hash"],
        "decision_hash": receipt["decision_hash"],
        "created_at_utc": "2026-01-01T00:00:02+00:00",
        "gateway_id": "tv_gateway",
        "protocol_version": "2.0.0",
    }

    stmt = receipt_to_attestation_statement(receipt, manifest)

    # Stable, schema-first structure
    assert set(stmt.keys()) == {"_type", "subject", "predicateType", "predicate", "metadata"}
    assert isinstance(stmt["subject"], list) and len(stmt["subject"]) == 1
    assert set(stmt["subject"][0].keys()) == {"action_id", "receipt_id", "tool_name"}

    # Validate via schema tooling on a single JSON file
    out = tmp_path / "attestation.statement.json"
    out.write_text(json.dumps(stmt, indent=2), encoding="utf-8")
    ok, msgs = validate_file(out)
    assert ok, [m.detail for m in msgs if not m.ok]


def test_audit_pack_exports_attestations_jsonl_and_validates(tmp_path: Path):
    from lap_gateway.audit_pack import AuditPackBuilder
    from lap_schema_validate import validate_file

    repo = Path(__file__).resolve().parents[1]

    evidence = json.loads((repo / "spec" / "test_vectors" / "evidence_basic.json").read_text(encoding="utf-8"))
    decision = json.loads((repo / "spec" / "test_vectors" / "decision_basic.json").read_text(encoding="utf-8"))
    receipt = json.loads((repo / "spec" / "test_vectors" / "receipt_basic.json").read_text(encoding="utf-8"))

    builder = AuditPackBuilder(gateway_id="tv_gateway", protocol_version="2.0.0")
    contents = builder.build_pack(
        action_id=evidence["action_id"],
        evidence=evidence,
        decision=decision,
        receipts=[receipt],
        trusted_keys={"tv_gateway_new": "deadbeef"},
    )

    zip_path = tmp_path / "pack.zip"
    created = builder.write_pack(contents, str(zip_path))
    assert Path(created).exists()

    # Extract and validate attestations.jsonl lines
    import zipfile

    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()
    with zipfile.ZipFile(created, "r") as zf:
        zf.extractall(extract_dir)

    att = extract_dir / "attestations.jsonl"
    assert att.exists()

    ok, msgs = validate_file(att)
    assert ok, [m.detail for m in msgs if not m.ok]