import pytest

from lap_gateway.audit_pack import AuditPackBuilder
from lap_gateway.crypto import canonical_json_dumps_v2, _sha256_hex, _safe_hash_encode


def _compute_hashes(action_id: str, evidence: dict, decision: dict):
    evidence_canon = canonical_json_dumps_v2(evidence)
    evidence_hash = _sha256_hex(evidence_canon.encode("utf-8"))
    decision_hash = _sha256_hex(_safe_hash_encode([
        action_id,
        evidence_hash,
        decision.get("outcome", ""),
        decision.get("tier", ""),
        decision.get("reason", ""),
    ]))
    return evidence_hash, decision_hash


def test_builder_rejects_token_hash_mismatch():
    action_id = "act_test_123"
    evidence = {"x": 1, "y": "z"}
    decision = {"outcome": "allow", "tier": "T1", "reason": "ok"}
    evidence_hash, decision_hash = _compute_hashes(action_id, evidence, decision)

    # Corrupt token hashes (do not match evidence/decision)
    token = {
        "key_id": "k1",
        "signed_at_utc": "2026-01-01T00:00:00Z",
        "payload": {
            "sub": "agent",
            "action_id": action_id,
            "evidence_hash": "00"*32,
            "decision_hash": decision_hash,
        },
        "signature": "AA==",
    }

    builder = AuditPackBuilder(gateway_id="gw", canonical_json_version="v2")
    with pytest.raises(ValueError, match="Evidence dict does not match governed evidence_hash"):
        builder.build_pack(action_id=action_id, evidence=evidence, decision=decision, token=token, receipts=[])


def test_builder_rejects_token_receipt_disagreement():
    action_id = "act_test_456"
    evidence = {"x": 2}
    decision = {"outcome": "deny", "tier": "T2", "reason": "nope"}
    evidence_hash, decision_hash = _compute_hashes(action_id, evidence, decision)

    token = {
        "key_id": "k1",
        "signed_at_utc": "2026-01-01T00:00:00Z",
        "payload": {
            "sub": "agent",
            "action_id": action_id,
            "evidence_hash": evidence_hash,
            "decision_hash": decision_hash,
        },
        "signature": "AA==",
    }

    # Receipts disagree with token evidence hash
    receipts = [{"evidence_hash": "11"*32, "decision_hash": decision_hash}]

    builder = AuditPackBuilder(gateway_id="gw", canonical_json_version="v2")
    with pytest.raises(ValueError, match="Evidence hash mismatch between token and receipts"):
        builder.build_pack(action_id=action_id, evidence=evidence, decision=decision, token=token, receipts=receipts)


def test_builder_accepts_matching_token_hashes():
    action_id = "act_test_789"
    evidence = {"x": 3, "nested": {"a": True}}
    decision = {"outcome": "allow", "tier": "T3", "reason": "fine"}
    evidence_hash, decision_hash = _compute_hashes(action_id, evidence, decision)

    token = {
        "key_id": "k1",
        "signed_at_utc": "2026-01-01T00:00:00Z",
        "payload": {
            "sub": "agent",
            "action_id": action_id,
            "evidence_hash": evidence_hash,
            "decision_hash": decision_hash,
        },
        "signature": "AA==",
    }

    builder = AuditPackBuilder(gateway_id="gw", canonical_json_version="v2")
    contents = builder.build_pack(action_id=action_id, evidence=evidence, decision=decision, token=token, receipts=[])
    assert contents.evidence_hash == evidence_hash
    assert contents.decision_hash == decision_hash
