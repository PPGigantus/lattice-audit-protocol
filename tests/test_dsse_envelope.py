import json
from pathlib import Path


def test_dsse_envelope_roundtrip_sign_verify_and_schema(tmp_path: Path):
    from lap_gateway.crypto import Ed25519KeyPair, TrustedKeyStore
    from lap_gateway.dsse import make_envelope, sign_envelope, verify_envelope
    from lap_schema_validate import validate_file

    # Create a minimal payload (bytes) to envelope
    payload_type = "https://lattice-audit-protocol.dev/attestation/v1"
    payload_obj = {"hello": "world", "n": 1}
    payload_bytes = json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    signing = Ed25519KeyPair.generate("gw")
    trusted = TrustedKeyStore.from_config({signing.key_id: signing.public_key_hex})

    env = make_envelope(payload_type, payload_bytes)
    env = sign_envelope(env, {signing.key_id: signing}, signing.key_id)

    assert verify_envelope(env, trusted) is True

    out = tmp_path / "attestation.dsse.json"
    out.write_text(json.dumps(env, indent=2, ensure_ascii=False), encoding="utf-8")

    ok, msgs = validate_file(out)
    assert ok, [m.detail for m in msgs if not m.ok]


def test_audit_pack_optional_exports_statement_and_dsse(tmp_path: Path):
    from lap_gateway.audit_pack import AuditPackBuilder
    from lap_gateway.crypto import Ed25519KeyPair, TrustedKeyStore
    from lap_gateway.dsse import verify_envelope
    from lap_schema_validate import validate_file

    repo = Path(__file__).resolve().parents[1]
    evidence = json.loads((repo / "spec" / "test_vectors" / "evidence_basic.json").read_text(encoding="utf-8"))
    decision = json.loads((repo / "spec" / "test_vectors" / "decision_basic.json").read_text(encoding="utf-8"))
    receipt = json.loads((repo / "spec" / "test_vectors" / "receipt_basic.json").read_text(encoding="utf-8"))

    signing = Ed25519KeyPair.generate("gw")
    trusted = TrustedKeyStore.from_config({signing.key_id: signing.public_key_hex})

    builder = AuditPackBuilder(gateway_id="tv_gateway", protocol_version="2.0.0")
    contents = builder.build_pack(
        action_id=evidence["action_id"],
        evidence=evidence,
        decision=decision,
        receipts=[receipt],
        trusted_keys={"tv_gateway_new": "deadbeef"},
    )

    zip_path = tmp_path / "pack.zip"
    created = builder.write_pack(
        contents,
        str(zip_path),
        export_attestation_files=True,
        dsse_key_store={signing.key_id: signing},
        dsse_key_id=signing.key_id,
    )
    assert Path(created).exists()

    import zipfile

    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()
    with zipfile.ZipFile(created, "r") as zf:
        zf.extractall(extract_dir)

    stmt = extract_dir / "attestation.statement.json"
    envf = extract_dir / "attestation.dsse.json"
    assert stmt.exists()
    assert envf.exists()

    ok_s, msgs_s = validate_file(stmt)
    assert ok_s, [m.detail for m in msgs_s if not m.ok]

    ok_e, msgs_e = validate_file(envf)
    assert ok_e, [m.detail for m in msgs_e if not m.ok]

    env = json.loads(envf.read_text(encoding="utf-8"))
    assert verify_envelope(env, trusted) is True
