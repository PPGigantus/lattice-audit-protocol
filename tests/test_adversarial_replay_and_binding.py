from __future__ import annotations

import json
from datetime import datetime, timezone
import pytest

from lap_gateway.crypto import Ed25519KeyPair, CRYPTO_AVAILABLE
from lap_gateway.receipts import ReceiptIssuer
from lap_gateway.tokens import TokenIssuer
from lap_gateway.server import GatewayStore
from lap_gateway.crypto import canonical_json_dumps
from lap_verify import verify_audit_pack_dir


def _deterministic_key(key_id: str, byte: int) -> Ed25519KeyPair:
    """Deterministic Ed25519 key for tests (no flakiness)."""
    if not CRYPTO_AVAILABLE:
        pytest.skip("cryptography not available; deterministic Ed25519 keys require CRYPTO_AVAILABLE")
    seed = bytes([byte]) * 32
    return Ed25519KeyPair.from_seed(seed, key_id=key_id)


def test_replay_across_restarts_nonce_and_counter(tmp_path):
    """Replay state should persist across store restarts (sqlite-backed)."""
    db_path = tmp_path / "gw.db"

    s1 = GatewayStore(db_path=str(db_path))
    ok, reason = s1.check_and_record_nonce("jti_nonce", "n1")
    assert ok, reason

    # Restart (new GatewayStore instance backed by the same DB)
    s2 = GatewayStore(db_path=str(db_path))
    ok2, reason2 = s2.check_and_record_nonce("jti_nonce", "n1")
    assert not ok2
    assert "NONCE_REUSED" in reason2

    ok3, reason3 = s2.check_and_update_counter("jti_ctr", 1)
    assert ok3, reason3

    # Restart again and attempt to replay old counter
    s3 = GatewayStore(db_path=str(db_path))
    ok4, reason4 = s3.check_and_update_counter("jti_ctr", 1)
    assert not ok4
    assert "COUNTER_NOT_MONOTONIC" in reason4

    # Next counter should be accepted
    ok5, reason5 = s3.check_and_update_counter("jti_ctr", 2)
    assert ok5, reason5


def _sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _safe_hash_encode(components) -> bytes:
    out = b""
    for c in components:
        b = str(c).encode("utf-8")
        out += len(b).to_bytes(8, "big") + b
    return out


def test_receipt_chain_break_detected_by_offline_verifier(tmp_path):
    """Offline verifier must detect a broken prev_receipt_hash chain."""
    pack_dir = tmp_path / "pack"
    pack_dir.mkdir()

    action_id = "A_CHAIN_1"
    evidence_obj = {"action_id": action_id, "description": "x" * 80}
    evidence_canon = canonical_json_dumps(evidence_obj, version="v1")
    evidence_hash = _sha256_hex(evidence_canon.encode("utf-8"))

    decision_obj = {"outcome": "approve", "tier": "T1_SENSITIVE", "reason": "ok"}
    decision_hash = _sha256_hex(_safe_hash_encode([action_id, evidence_hash, "approve", "T1_SENSITIVE", "ok"]))

    (pack_dir / "evidence.json").write_text(json.dumps(evidence_obj, indent=2), encoding="utf-8")
    (pack_dir / "decision.json").write_text(json.dumps(decision_obj, indent=2), encoding="utf-8")
    (pack_dir / "manifest.json").write_text(
        json.dumps(
            {
                "action_id": action_id,
                "evidence_hash": evidence_hash,
                "decision_hash": decision_hash,
                "canonical_json_version": "v1",
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    key = _deterministic_key("k_test", 7)
    (pack_dir / "trusted_keys.json").write_text(json.dumps({key.key_id: key.public_key_hex()}, indent=2), encoding="utf-8")

    issuer = ReceiptIssuer(key)
    t0 = datetime(2026, 1, 13, 12, 0, 0, tzinfo=timezone.utc)

    r1 = issuer.issue_receipt(
        action_id=action_id,
        evidence_hash=evidence_hash,
        decision_hash=decision_hash,
        token_jti="jti1",
        tool_name="tool",
        operation="execute",
        params={"x": 1},
        result={"ok": True},
        response_envelope={"success": True, "result": {"ok": True}, "error": None},
        result_status="success",
        invoked_at=t0,
        completed_at=t0,
    )

    r2 = issuer.issue_receipt(
        action_id=action_id,
        evidence_hash=evidence_hash,
        decision_hash=decision_hash,
        token_jti="jti1",
        tool_name="tool",
        operation="execute",
        params={"x": 2},
        result={"ok": True},
        response_envelope={"success": True, "result": {"ok": True}, "error": None},
        result_status="success",
        invoked_at=t0,
        completed_at=t0,
    )

    receipts_path = pack_dir / "receipts.json"
    receipts_path.write_text(json.dumps([r1.to_dict(), r2.to_dict()], indent=2), encoding="utf-8")

    ok, msgs = verify_audit_pack_dir(pack_dir)
    assert ok, [m.code for m in msgs]

    # Break chain
    broken = json.loads(receipts_path.read_text(encoding="utf-8"))
    broken[1]["prev_receipt_hash"] = "deadbeef" * 8
    receipts_path.write_text(json.dumps(broken, indent=2), encoding="utf-8")

    ok2, msgs2 = verify_audit_pack_dir(pack_dir)
    assert not ok2
    assert any(m.code == "RECEIPT_CHAIN_BROKEN" for m in msgs2)


def test_mismatched_decision_token_binding_rejected(tmp_path):
    """If a token points at a decision_hash that doesn't exist, enforcement must fail closed."""
    db_path = tmp_path / "gw.db"
    store = GatewayStore(db_path=str(db_path))

    action_id = "ACTION_BIND_1"
    evidence_hash = "a" * 64

    # Store the *real* decision (approve) under decision_hash = h1
    store.store_decision(
        decision_id="dec1",
        action_id=action_id,
        evidence_hash=evidence_hash,
        decision_hash="h1",
        outcome="approve",
        tier="T1_SENSITIVE",
        reason="ok",
        agent_id="agent_001",
    )

    # Issue a token bound to a *different* decision_hash (h2)
    key = _deterministic_key("k_tok", 11)
    issuer = TokenIssuer("gw", key)
    token = issuer.issue_token(
        subject="agent_001",
        action_id=action_id,
        evidence_hash=evidence_hash,
        decision_hash="h2",
        tier="T1_SENSITIVE",
        allowed_tools=["tool"],
        allowed_ops=["execute"],
        sid="sess_001",
    )
    store.store_token(token)

    reserved, reason = store.atomic_reserve_budget(
        jti=token.jti,
        action_id=token.action_id,
        evidence_hash=token.evidence_hash,
        decision_hash=token.decision_hash,
        budget=token.budget.to_dict(),
        add_calls=1,
        add_bytes_in=1,
        reserve_bytes_out=1,
    )

    assert not reserved
    assert reason == "DECISION_NOT_FOUND"
