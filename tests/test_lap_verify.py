import json
import tempfile
from pathlib import Path
from datetime import datetime, timezone


def test_lap_verify_audit_pack_with_invocations():
    """lap-verify should validate receipts + response hash commitments when invocations.json is provided."""

    from lap_gateway.crypto import create_key_pair
    from lap_gateway.tokens import TokenIssuer
    from lap_gateway.receipts import ReceiptIssuer
    from lap_gateway.audit_pack import AuditPackBuilder
    from lap_verify import verify_audit_pack_path

    gw_kp = create_key_pair("gw_verify")

    # Minimal evidence/decision
    evidence = {
        "action_id": "ACT_VERIFY_001",
        "description": "Read-only test action",
        "timestamp_utc": "2026-01-10T00:00:00+00:00",
        "irreversibility": {"score": 0.1, "reversibility_plan": "No changes"},
        "outcome_delta": {},
        "necessity_confidence": 0.9,
        "novelty_loss_estimate": 0.0,
        "novelty_method": "",
        "suffering_risk_estimate": 0.0,
        "suffering_method": "",
        "provenance": {},
        "alternatives": [{"description": "Do nothing"}],
        "attestations": [],
    }
    decision = {"outcome": "approve", "tier": "T1_SENSITIVE", "reason": "test"}

    builder = AuditPackBuilder(gateway_id="test_gateway", protocol_version="1.0.0")
    contents = builder.build_pack(action_id=evidence["action_id"], evidence=evidence, decision=decision)

    # Token bound to pack
    token_issuer = TokenIssuer(issuer_id="test_gateway", signing_key=gw_kp)
    token = token_issuer.issue_token(
        subject="agent_001",
        action_id=evidence["action_id"],
        evidence_hash=contents.evidence_hash,
        decision_hash=contents.decision_hash,
        tier="T1_SENSITIVE",
        allowed_tools=["mock"],
        allowed_ops=["execute"],
        ttl_seconds=60,
    )

    # Receipt bound to token
    receipt_issuer = ReceiptIssuer(signing_key=gw_kp)
    params = {"x": 1}
    result = {"ok": True}
    response_envelope = {"success": True, "result": result, "error": None}
    receipt = receipt_issuer.issue_receipt(
        action_id=evidence["action_id"],
        evidence_hash=contents.evidence_hash,
        decision_hash=contents.decision_hash,
        token_jti=token.jti,
        tool_name="mock",
        operation="execute",
        params=params,
        result=result,
        response_envelope=response_envelope,
        result_status="success",
        invoked_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )

    receipts = [receipt.to_dict()]
    invocations = [
        {
            "receipt_id": receipt.receipt_id,
            "params": params,
            "result": result,
            "response_envelope": response_envelope,
        }
    ]

    # Build final pack with token, receipts, invocations, and trusted key
    contents = builder.build_pack(
        action_id=evidence["action_id"],
        evidence=evidence,
        decision=decision,
        token=token.to_dict(),
        receipts=receipts,
        invocations=invocations,
        trusted_keys={gw_kp.key_id: gw_kp.public_key_hex},
    )

    with tempfile.TemporaryDirectory() as td:
        pack_path = str(Path(td) / "pack.zip")
        builder.write_pack(contents, pack_path)

        ok, msgs = verify_audit_pack_path(pack_path, skip_signatures=False, require_invocations_for_hash_checks=True)
        assert ok, "\n".join([f"{m.ok} {m.code} {m.detail}" for m in msgs])


def test_lap_verify_rejects_tampered_invocation_payload():
    """If invocations.json is tampered, lap-verify should fail hash-commit checks."""
    from lap_gateway.crypto import create_key_pair
    from lap_gateway.tokens import TokenIssuer
    from lap_gateway.receipts import ReceiptIssuer
    from lap_gateway.audit_pack import AuditPackBuilder
    from lap_verify import verify_audit_pack_path

    gw_kp = create_key_pair("gw_verify2")

    evidence = {
        "action_id": "ACT_VERIFY_002",
        "description": "Read-only test action",
        "timestamp_utc": "2026-01-10T00:00:00+00:00",
        "irreversibility": {"score": 0.1, "reversibility_plan": "No changes"},
        "outcome_delta": {},
        "necessity_confidence": 0.9,
        "novelty_loss_estimate": 0.0,
        "novelty_method": "",
        "suffering_risk_estimate": 0.0,
        "suffering_method": "",
        "provenance": {},
        "alternatives": [{"description": "Do nothing"}],
        "attestations": [],
    }
    decision = {"outcome": "approve", "tier": "T1_SENSITIVE", "reason": "test"}
    builder = AuditPackBuilder(gateway_id="test_gateway", protocol_version="1.0.0")
    base = builder.build_pack(action_id=evidence["action_id"], evidence=evidence, decision=decision)

    token_issuer = TokenIssuer(issuer_id="test_gateway", signing_key=gw_kp)
    token = token_issuer.issue_token(
        subject="agent_001",
        action_id=evidence["action_id"],
        evidence_hash=base.evidence_hash,
        decision_hash=base.decision_hash,
        tier="T1_SENSITIVE",
        allowed_tools=["mock"],
        allowed_ops=["execute"],
        ttl_seconds=60,
    )
    receipt_issuer = ReceiptIssuer(signing_key=gw_kp)
    params = {"x": 1}
    result = {"ok": True}
    response_envelope = {"success": True, "result": result, "error": None}
    receipt = receipt_issuer.issue_receipt(
        action_id=evidence["action_id"],
        evidence_hash=base.evidence_hash,
        decision_hash=base.decision_hash,
        token_jti=token.jti,
        tool_name="mock",
        operation="execute",
        params=params,
        result=result,
        response_envelope=response_envelope,
        result_status="success",
        invoked_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )

    receipts = [receipt.to_dict()]
    invocations = [
        {
            "receipt_id": receipt.receipt_id,
            "params": {"x": 999},  # tampered
            "result": result,
            "response_envelope": response_envelope,
        }
    ]

    contents = builder.build_pack(
        action_id=evidence["action_id"],
        evidence=evidence,
        decision=decision,
        token=token.to_dict(),
        receipts=receipts,
        invocations=invocations,
        trusted_keys={gw_kp.key_id: gw_kp.public_key_hex},
    )

    with tempfile.TemporaryDirectory() as td:
        pack_path = str(Path(td) / "pack.zip")
        builder.write_pack(contents, pack_path)
        ok, msgs = verify_audit_pack_path(pack_path, skip_signatures=False, require_invocations_for_hash_checks=True)
        assert not ok
        assert any(m.code == "PARAMS_HASH_MISMATCH" for m in msgs)
