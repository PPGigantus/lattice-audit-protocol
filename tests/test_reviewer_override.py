from datetime import datetime, timezone

import pytest

from lap_gateway.server import LAPGateway, GatewayStore
from lap_gateway.crypto import create_key_pair, Ed25519ExternalApproval
from lap_gateway.evidence_quality import EvidenceQualityChecker, EvidenceQualityPolicy


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


def test_evidence_quality_flags_reviewer_override_for_semantic_minimalism():
    # Relax lengths slightly so we can craft a low-entropy but long-enough payload.
    policy = EvidenceQualityPolicy.relaxed()
    policy.min_description_entropy = 3.0
    checker = EvidenceQualityChecker(policy)

    # Low-entropy, repetitive content (structurally present).
    evidence = {
        "action_id": "A1",
        "description": ("a " * 400).strip(),
        "irreversibility": {"score": 0.9, "reversibility_plan": ("b " * 200).strip()},
        "alternatives": [{"description": "alt"}],
    }

    ok, issues, requires_override = checker.check_evidence_detailed(evidence, "T3_CATASTROPHIC")
    assert ok is True
    assert requires_override is True
    assert issues  # should report at least LOW_ENTROPY/HIGH_REPETITION/etc.


@pytest.mark.asyncio
async def test_t3_mint_requires_reviewer_override_when_decision_marked(tmp_path, monkeypatch):
    monkeypatch.setenv("LAP_T3_REQUIRED_ROLES", "PrimaryDecider,SafetyCritic")
    monkeypatch.setenv("LAP_REVIEWER_OVERRIDE_ROLE", "ReviewerOverride")

    store = GatewayStore(db_path=str(tmp_path / "gateway.db"))
    gateway_key = create_key_pair("gw_key")
    gateway = LAPGateway(signing_key=gateway_key, store=store)

    # Create and trust three reviewer keys
    pd_key = create_key_pair("pd_key")
    sc_key = create_key_pair("sc_key")
    ro_key = create_key_pair("ro_key")
    gateway.trusted_keys.add_public_key(pd_key.key_id, pd_key.public_key_hex)
    gateway.trusted_keys.add_public_key(sc_key.key_id, sc_key.public_key_hex)
    gateway.trusted_keys.add_public_key(ro_key.key_id, ro_key.public_key_hex)

    action_id = "act_t3_override"
    evidence = {"action_id": action_id, "description": "t3", "irreversibility": {"score": 0.9}}
    evidence_hash = gateway._compute_evidence_hash(evidence)
    decision_reason = "ok | REQUIRES_REVIEWER_OVERRIDE: LOW_ENTROPY"
    decision_hash = gateway._compute_decision_hash(
        action_id, evidence_hash, "approve", "T3_CATASTROPHIC", decision_reason
    )
    store.store_decision(
        decision_id="d1",
        action_id=action_id,
        evidence_hash=evidence_hash,
        decision_hash=decision_hash,
        outcome="approve",
        tier="T3_CATASTROPHIC",
        reason=decision_reason,
        agent_id="agent",
    )

    # Record PrimaryDecider + SafetyCritic approvals -> should STILL fail (missing reviewer override)
    approval_pd = _make_signed_approval(
        action_id=action_id, evidence_hash=evidence_hash, reviewer_type="PrimaryDecider", key_pair=pd_key
    )
    approval_sc = _make_signed_approval(
        action_id=action_id, evidence_hash=evidence_hash, reviewer_type="SafetyCritic", key_pair=sc_key
    )
    ok, _ = await gateway.record_external_approval(approval_pd)
    assert ok is True
    ok, _ = await gateway.record_external_approval(approval_sc)
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
    assert "ReviewerOverride" in res["error"]

    # Add reviewer override approval -> mint should succeed
    approval_ro = _make_signed_approval(
        action_id=action_id, evidence_hash=evidence_hash, reviewer_type="ReviewerOverride", key_pair=ro_key
    )
    ok, _ = await gateway.record_external_approval(approval_ro)
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
