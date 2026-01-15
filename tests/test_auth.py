import json


from lap_gateway.auth import ApiKeyAuth, ENV_API_KEYS_JSON, ENV_API_KEYS_FILE


def test_auth_disabled_allows_claimed_identity(monkeypatch):
    monkeypatch.delenv(ENV_API_KEYS_JSON, raising=False)
    monkeypatch.delenv(ENV_API_KEYS_FILE, raising=False)

    auth = ApiKeyAuth.load_from_env()
    assert auth.enabled() is False

    agent_id, err = auth.resolve_identity(api_key=None, claimed_agent_id="alice")
    assert agent_id == "alice"
    assert err is None


def test_auth_configured_requires_api_key(monkeypatch):
    monkeypatch.setenv(ENV_API_KEYS_JSON, json.dumps({"k1": "alice"}))
    monkeypatch.delenv(ENV_API_KEYS_FILE, raising=False)

    auth = ApiKeyAuth.load_from_env()
    assert auth.enabled() is True

    agent_id, err = auth.resolve_identity(api_key=None, claimed_agent_id="alice")
    assert agent_id is None
    assert err == "API_KEY_REQUIRED"


def test_auth_valid_key_resolves_identity_and_checks_claim(monkeypatch):
    monkeypatch.setenv(ENV_API_KEYS_JSON, json.dumps({"k1": "alice"}))
    monkeypatch.delenv(ENV_API_KEYS_FILE, raising=False)

    auth = ApiKeyAuth.load_from_env()

    agent_id, err = auth.resolve_identity(api_key="k1", claimed_agent_id=None)
    assert agent_id == "alice"
    assert err is None

    # Claim mismatch should be rejected
    agent_id, err = auth.resolve_identity(api_key="k1", claimed_agent_id="bob")
    assert agent_id is None
    assert err == "AGENT_ID_MISMATCH"


def test_auth_invalid_key_rejected(monkeypatch):
    monkeypatch.setenv(ENV_API_KEYS_JSON, json.dumps({"k1": "alice"}))
    monkeypatch.delenv(ENV_API_KEYS_FILE, raising=False)

    auth = ApiKeyAuth.load_from_env()

    agent_id, err = auth.resolve_identity(api_key="nope", claimed_agent_id="alice")
    assert agent_id is None
    assert err == "API_KEY_INVALID"


def test_auth_malformed_config_fails_closed(monkeypatch):
    # If the deployer sets env but it's malformed, fail closed.
    monkeypatch.setenv(ENV_API_KEYS_JSON, "not json")
    monkeypatch.delenv(ENV_API_KEYS_FILE, raising=False)

    auth = ApiKeyAuth.load_from_env()
    assert auth.enabled() is True

    agent_id, err = auth.resolve_identity(api_key=None, claimed_agent_id="alice")
    assert agent_id is None
    assert err == "API_KEY_CONFIG_INVALID"


def test_auth_file_config(monkeypatch, tmp_path):
    p = tmp_path / "keys.json"
    p.write_text(json.dumps({"k2": "carol"}), encoding="utf-8")

    monkeypatch.delenv(ENV_API_KEYS_JSON, raising=False)
    monkeypatch.setenv(ENV_API_KEYS_FILE, str(p))

    auth = ApiKeyAuth.load_from_env()
    assert auth.enabled() is True

    agent_id, err = auth.resolve_identity(api_key="k2", claimed_agent_id="carol")
    assert agent_id == "carol"
    assert err is None
