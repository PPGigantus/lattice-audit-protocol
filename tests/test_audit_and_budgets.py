import json
from pathlib import Path

import pytest

from lap_gateway.audit_log import TamperEvidentAuditLog
from lap_gateway.crypto import create_key_pair, TrustedKeyStore
from lap_gateway.server import LAPGateway, GatewayStore, MockToolConnector
from lap_gateway.tokens import TokenBudget


def test_tamper_evident_audit_log_detects_modification(tmp_path: Path):
    key = create_key_pair("test_audit_key")
    log_path = tmp_path / "audit.jsonl"
    log = TamperEvidentAuditLog(str(log_path), key)

    log.append_event({"type": "t", "n": 1})
    log.append_event({"type": "t", "n": 2})

    ks = TrustedKeyStore.from_config({key.key_id: key.public_key_hex()})
    ok, reason, count = TamperEvidentAuditLog.verify_file(str(log_path), ks)
    assert ok, reason
    assert count == 2

    # Tamper with the second line
    lines = log_path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["event"]["n"] = 999
    lines[1] = json.dumps(rec, sort_keys=True)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok2, reason2, _ = TamperEvidentAuditLog.verify_file(str(log_path), ks)
    assert not ok2
    assert reason2 in {"EVENT_HASH_MISMATCH", "ENTRY_HASH_MISMATCH", "INVALID_SIGNATURE", "CHAIN_BROKEN"}


class LargeOutputConnector(MockToolConnector):
    async def invoke(self, operation, params, credentials=None):
        # Return a large payload to test bytes_out fail-closed
        return True, {"blob": "x" * 5000}, None


@pytest.mark.asyncio
async def test_bytes_out_budget_fail_closed(tmp_path: Path):
    # Isolated DB
    db_path = tmp_path / "gateway.db"
    store = GatewayStore(db_path=str(db_path))

    gateway = LAPGateway(gateway_id="g1", signing_key=create_key_pair("g1_test_key"), store=store)
    gateway.register_tool(LargeOutputConnector("mock"))

    action_id = "act1"
    evidence = {"action_id": action_id, "description": "test"}
    evidence_hash = gateway._compute_evidence_hash(evidence)
    decision_hash = gateway._compute_decision_hash(action_id, evidence_hash, "approve", "T1_SENSITIVE", "ok")
    gateway.store.store_decision("dec1", action_id, evidence_hash, decision_hash, "approve", "T1_SENSITIVE", "ok", "agent")

    # Issue token with very small max_bytes_out
    budget = TokenBudget(max_calls=1, max_bytes_in=10_000, max_bytes_out=200, max_spend_cents=0, max_duration_seconds=60)
    token = gateway.token_issuer.issue_token(
        action_id=action_id,
        evidence_hash=evidence_hash,
        decision_hash=decision_hash,
        tier="T1_SENSITIVE",
        subject="agent",
        allowed_tools=["mock"],
        allowed_ops=["execute"],
        budget=budget,
    )

    # Persist token (required by atomic_reserve_budget)
    gateway.store.store_token(token)

    res = await gateway.invoke_tool(
        tool_name="mock",
        operation="execute",
        params={"a": 1},
        token_compact=token.to_compact(),
        caller_id="agent",
        session_id=None,
        nonce=None,
        counter=None,
    )

    assert res["success"] is False
    assert "BYTES_OUT_BUDGET_EXCEEDED" in (res.get("error") or "")
    assert isinstance(res.get("result"), dict)
    assert res["result"].get("withheld") is True
