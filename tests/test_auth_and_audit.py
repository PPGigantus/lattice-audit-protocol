import json

import pytest

from lap_gateway.audit_log import TamperEvidentAuditLog
from lap_gateway.auth import ApiKeyAuth, ENV_API_KEYS_FILE, ENV_API_KEYS_JSON
from lap_gateway.crypto import Ed25519KeyPair, TrustedKeyStore


# -----------------------
# Auth tests (comprehensive)
# -----------------------

def test_auth_env_json_enabled_requires_key(monkeypatch):
    monkeypatch.setenv(ENV_API_KEYS_JSON, json.dumps({"k1": "agentA"}))
    auth = ApiKeyAuth.load_from_env()
    assert auth.enabled()

    agent, err = auth.resolve_identity(api_key=None, claimed_agent_id="agentA")
    assert agent is None
    assert err == "API_KEY_REQUIRED"


def test_auth_env_json_valid_key_resolves_agent(monkeypatch):
    monkeypatch.setenv(ENV_API_KEYS_JSON, json.dumps({"k1": "agentA"}))
    auth = ApiKeyAuth.load_from_env()

    agent, err = auth.resolve_identity(api_key="k1", claimed_agent_id=None)
    assert err is None
    assert agent == "agentA"


def test_auth_env_json_claimed_mismatch_fails_closed(monkeypatch):
    monkeypatch.setenv(ENV_API_KEYS_JSON, json.dumps({"k1": "agentA"}))
    auth = ApiKeyAuth.load_from_env()

    agent, err = auth.resolve_identity(api_key="k1", claimed_agent_id="agentB")
    assert agent is None
    assert err == "AGENT_ID_MISMATCH"


def test_auth_malformed_config_fails_closed(monkeypatch):
    monkeypatch.setenv(ENV_API_KEYS_JSON, "not-json")
    auth = ApiKeyAuth.load_from_env()
    assert auth.enabled()
    assert auth.config_error == "API_KEY_CONFIG_INVALID"

    agent, err = auth.resolve_identity(api_key="anything", claimed_agent_id="agentA")
    assert agent is None
    assert err == "API_KEY_CONFIG_INVALID"


def test_auth_file_mapping(monkeypatch, tmp_path):
    mapping_path = tmp_path / "keys.json"
    mapping_path.write_text(json.dumps({"k2": "agentB"}), encoding="utf-8")

    monkeypatch.delenv(ENV_API_KEYS_JSON, raising=False)
    monkeypatch.setenv(ENV_API_KEYS_FILE, str(mapping_path))

    auth = ApiKeyAuth.load_from_env()
    assert auth.enabled()

    agent, err = auth.resolve_identity(api_key="k2", claimed_agent_id="agentB")
    assert err is None
    assert agent == "agentB"


def test_auth_disabled_allows_claimed_identity(monkeypatch):
    monkeypatch.delenv(ENV_API_KEYS_JSON, raising=False)
    monkeypatch.delenv(ENV_API_KEYS_FILE, raising=False)

    auth = ApiKeyAuth.load_from_env()
    assert not auth.enabled()

    agent, err = auth.resolve_identity(api_key=None, claimed_agent_id="agentX")
    assert err is None
    assert agent == "agentX"


# -----------------------
# Audit log tests (comprehensive)
# -----------------------

def _make_keys():
    signing = Ed25519KeyPair.generate("sign")
    trusted = TrustedKeyStore.from_config({signing.key_id: signing.public_key_hex})
    return signing, trusted


def test_audit_log_verify_ok_and_resume(tmp_path):
    signing, trusted = _make_keys()
    log_path = tmp_path / "audit.jsonl"

    log = TamperEvidentAuditLog(str(log_path), signing)
    log.append_event({"a": 1})

    # Re-open to ensure resume (reads last hash) works
    log2 = TamperEvidentAuditLog(str(log_path), signing)
    log2.append_event({"b": 2})

    ok, reason, count = TamperEvidentAuditLog.verify_file(str(log_path), trusted)
    assert ok is True
    assert reason == "OK"
    assert count == 2


def test_audit_log_chain_broken_detected(tmp_path):
    signing, trusted = _make_keys()
    log_path = tmp_path / "audit.jsonl"

    log = TamperEvidentAuditLog(str(log_path), signing)
    log.append_event({"a": 1})
    log.append_event({"b": 2})

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2

    # Break chain by changing prev_hash on second record
    rec2 = json.loads(lines[1])
    rec2["prev_hash"] = "f" * 64
    lines[1] = json.dumps(rec2, sort_keys=True)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, reason, count = TamperEvidentAuditLog.verify_file(str(log_path), trusted)
    assert ok is False
    assert reason == "CHAIN_BROKEN"
    assert count == 2


def test_audit_log_event_hash_mismatch_detected(tmp_path):
    signing, trusted = _make_keys()
    log_path = tmp_path / "audit.jsonl"

    log = TamperEvidentAuditLog(str(log_path), signing)
    log.append_event({"a": 1})

    rec = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    # Mutate event without updating event_hash/signature
    rec["event"] = {"a": 999}
    log_path.write_text(json.dumps(rec, sort_keys=True) + "\n", encoding="utf-8")

    ok, reason, count = TamperEvidentAuditLog.verify_file(str(log_path), trusted)
    assert ok is False
    assert reason == "EVENT_HASH_MISMATCH"
    assert count == 1


def test_audit_log_untrusted_key_detected(tmp_path):
    signing, _trusted = _make_keys()
    log_path = tmp_path / "audit.jsonl"

    log = TamperEvidentAuditLog(str(log_path), signing)
    log.append_event({"a": 1})

    # Verify with an empty trust store
    ok, reason, count = TamperEvidentAuditLog.verify_file(str(log_path), TrustedKeyStore.from_config({}))
    assert ok is False
    assert reason == "INVALID_SIGNATURE"
    assert count == 1


def test_audit_log_invalid_signature_detected(tmp_path):
    signing, trusted = _make_keys()
    log_path = tmp_path / "audit.jsonl"

    log = TamperEvidentAuditLog(str(log_path), signing)
    log.append_event({"a": 1})

    rec = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    # Corrupt signature
    rec["signature_b64"] = "AAAA"  # decodes but invalid
    log_path.write_text(json.dumps(rec, sort_keys=True) + "\n", encoding="utf-8")

    ok, reason, count = TamperEvidentAuditLog.verify_file(str(log_path), trusted)
    assert ok is False
    assert reason == "INVALID_SIGNATURE"
    assert count == 1


def test_audit_log_bad_version_detected(tmp_path):
    signing, trusted = _make_keys()
    log_path = tmp_path / "audit.jsonl"

    log = TamperEvidentAuditLog(str(log_path), signing)
    log.append_event({"a": 1})

    rec = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    rec["version"] = "NOPE"
    log_path.write_text(json.dumps(rec, sort_keys=True) + "\n", encoding="utf-8")

    ok, reason, count = TamperEvidentAuditLog.verify_file(str(log_path), trusted)
    assert ok is False
    assert reason.startswith("BAD_VERSION")
    assert count == 1
