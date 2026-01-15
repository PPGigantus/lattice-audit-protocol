from datetime import datetime, timezone

import pytest

from lap_gateway.server import LAPGateway, GatewayStore
from lap_gateway.crypto import create_key_pair, Ed25519ExternalApproval


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_signed_approval(*, action_id: str, evidence_hash: str, reviewer_type: str, key_pair):
    approval = Ed25519ExternalApproval(
        action_id=action_id,
        evidence_hash=evidence_hash,
        reviewer_id=f"{reviewer_type.lower()}_bot",
        reviewer_type=reviewer_type,
        decision="approve",
        confidence=0.99,
        reasoning="ok",
        conditions=[],
        reviewed_at_utc=_now_iso(),
        signature=b"",
        key_id=key_pair.key_id,
    )
    payload = approval.compute_signature_payload()
    approval.signature = key_pair.sign(payload)
    return approval


@pytest.mark.asyncio
async def test_t3_mint_requires_dual_approvals(tmp_path, monkeypatch):
    monkeypatch.setenv("LAP_T3_REQUIRED_ROLES", "PrimaryDecider,SafetyCritic")

    store = GatewayStore(db_path=str(tmp_path / "gateway.db"))
    gateway_key = create_key_pair("gw_key")
    gateway = LAPGateway(signing_key=gateway_key, store=store)

    # Create and trust two reviewer keys
    pd_key = create_key_pair("pd_key")
    sc_key = create_key_pair("sc_key")
    gateway.trusted_keys.add_public_key(pd_key.key_id, pd_key.public_key_hex)
    gateway.trusted_keys.add_public_key(sc_key.key_id, sc_key.public_key_hex)

    # Create a decision record for a T3 action (approve)
    action_id = "act_t3"
    evidence = {"action_id": action_id, "description": "t3", "irreversibility": 1.0}
    evidence_hash = gateway._compute_evidence_hash(evidence)
    decision_hash = gateway._compute_decision_hash(
        action_id, evidence_hash, "approve", "T3_CATASTROPHIC", "ok"
    )
    store.store_decision(
        decision_id="d1",
        action_id=action_id,
        evidence_hash=evidence_hash,
        decision_hash=decision_hash,
        outcome="approve",
        tier="T3_CATASTROPHIC",
        reason="ok",
        agent_id="agent",
    )

    # Record only one approval -> mint should fail
    approval_pd = _make_signed_approval(
        action_id=action_id,
        evidence_hash=evidence_hash,
        reviewer_type="PrimaryDecider",
        key_pair=pd_key,
    )
    ok, _ = await gateway.record_external_approval(approval_pd)
    assert ok is True

    sid, _ = store.create_session(agent_id="agent", ttl_seconds=3600)
    res = await gateway.mint_t3_token(
        action_id=action_id,
        evidence_hash=evidence_hash,
        decision_hash=decision_hash,
        tool_name="mock",
        operation="read",
        params={"x": 1},
        session_id=sid,
        agent_id="agent",
        caller_authenticated=True,
    )
    assert res["success"] is False
    assert "MISSING_EXTERNAL_APPROVALS" in res["error"]
    assert "SafetyCritic" in res["error"]

    # Add second role approval -> mint should succeed
    approval_sc = _make_signed_approval(
        action_id=action_id,
        evidence_hash=evidence_hash,
        reviewer_type="SafetyCritic",
        key_pair=sc_key,
    )
    ok, _ = await gateway.record_external_approval(approval_sc)
    assert ok is True

    res2 = await gateway.mint_t3_token(
        action_id=action_id,
        evidence_hash=evidence_hash,
        decision_hash=decision_hash,
        tool_name="mock",
        operation="read",
        params={"x": 1},
        session_id=sid,
        agent_id="agent",
        caller_authenticated=True,
    )
    assert res2["success"] is True
    assert isinstance(res2.get("capability_token"), str)
    assert res2.get("params_hash")
