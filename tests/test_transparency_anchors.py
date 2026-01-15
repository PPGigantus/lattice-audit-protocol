import json
from argparse import Namespace
from pathlib import Path


def test_transparency_anchor_entry_schema_validates_jsonl(tmp_path: Path):
    from lap_schema_validate import validate_file

    p = tmp_path / "anchors.jsonl"
    entry = {
        "timestamp_utc": "2026-01-01T00:00:00+00:00",
        "artifact_type": "receipt",
        "artifact_hash": "0" * 64,
        "key_id": "test_key",
        "signature": "QUJDREVGRw==",
    }
    p.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    ok, msgs = validate_file(p)
    assert ok, [m.detail for m in msgs if not m.ok]


def _load_vectors(repo: Path):
    evidence = json.loads((repo / "spec" / "test_vectors" / "evidence_basic.json").read_text(encoding="utf-8"))
    decision = json.loads((repo / "spec" / "test_vectors" / "decision_basic.json").read_text(encoding="utf-8"))
    receipt = json.loads((repo / "spec" / "test_vectors" / "receipt_basic.json").read_text(encoding="utf-8"))
    return evidence, decision, receipt


def test_audit_pack_optional_exports_anchors_and_hashes(tmp_path: Path):
    from lap_gateway.audit_pack import AuditPackBuilder
    from lap_gateway.crypto import Ed25519KeyPair
    from lap_schema_validate import validate_file

    repo = Path(__file__).resolve().parents[1]
    evidence, decision, receipt = _load_vectors(repo)

    # Deterministic signing key
    seed = b"0123456789abcdef0123456789abcdef"  # 32 bytes
    signing = Ed25519KeyPair.from_seed(seed, "gw")

    builder = AuditPackBuilder(gateway_id="tv_gateway", protocol_version="2.0.0")
    contents = builder.build_pack(
        action_id=evidence["action_id"],
        evidence=evidence,
        decision=decision,
        receipts=[receipt],
        trusted_keys={"tv_gateway_new": "deadbeef"},
    )

    # Freeze created_at_utc for deterministic attestation statement / DSSE envelope
    contents.created_at_utc = "2026-01-01T00:00:00+00:00"

    zip_path = tmp_path / "pack.zip"
    created = builder.write_pack(
        contents,
        str(zip_path),
        export_attestation_files=True,
        dsse_key_store={signing.key_id: signing},
        dsse_key_id=signing.key_id,
        export_anchors_jsonl=True,
        anchors_include_receipts=True,
        anchors_include_dsse=True,
    )
    assert Path(created).exists()

    import zipfile

    out_dir = tmp_path / "extracted"
    out_dir.mkdir()
    with zipfile.ZipFile(created, "r") as zf:
        zf.extractall(out_dir)

    anchors = out_dir / "anchors.jsonl"
    assert anchors.exists()

    ok, msgs = validate_file(anchors)
    assert ok, [m.detail for m in msgs if not m.ok]

    # Parse entries and ensure expected artifact hashes are present
    entries = [json.loads(line) for line in anchors.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert entries

    # These expected hashes are regression guards for the fixture inputs.
    # If they change, it indicates a breaking change to the canonicalization/hash policy.
    expected_receipt_hash = "6a6a3fa8696083442b65f36b27db642122552677dde2cd1cf41802e5a316ca9c"
    expected_env_hash = "5fd9fa043aad606d79a2297487ba1b5b6c0694b64398c815c5af919cae0796f3"

    got_receipt = any(e.get("artifact_type") == "receipt" and e.get("artifact_hash") == expected_receipt_hash for e in entries)
    got_env = any(e.get("artifact_type") == "attestation" and e.get("artifact_hash") == expected_env_hash for e in entries)
    assert got_receipt
    assert got_env


def test_lap_anchor_cli_creates_anchors_jsonl(tmp_path: Path):
    from lap_gateway.audit_pack import AuditPackBuilder
    from lap_gateway.crypto import Ed25519KeyPair
    from lap_cli import cmd_anchor
    from lap_schema_validate import validate_file

    repo = Path(__file__).resolve().parents[1]
    evidence, decision, receipt = _load_vectors(repo)

    seed = b"0123456789abcdef0123456789abcdef"  # 32 bytes
    signing = Ed25519KeyPair.from_seed(seed, "gw")

    builder = AuditPackBuilder(gateway_id="tv_gateway", protocol_version="2.0.0")
    contents = builder.build_pack(
        action_id=evidence["action_id"],
        evidence=evidence,
        decision=decision,
        receipts=[receipt],
        trusted_keys={"tv_gateway_new": "deadbeef"},
    )
    contents.created_at_utc = "2026-01-01T00:00:00+00:00"

    zip_path = tmp_path / "pack.zip"
    created = builder.write_pack(
        contents,
        str(zip_path),
        export_attestation_files=True,
        dsse_key_store={signing.key_id: signing},
        dsse_key_id=signing.key_id,
    )

    out = tmp_path / "anchors.jsonl"
    args = Namespace(
        pack=str(created),
        out=str(out),
        no_receipts=False,
        no_dsse=False,
        include_auditpack=False,
        append=False,
        fail_on_empty=True,
    )
    cmd_anchor(args)

    assert out.exists()
    ok, msgs = validate_file(out)
    assert ok, [m.detail for m in msgs if not m.ok]
