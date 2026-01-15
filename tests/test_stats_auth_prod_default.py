import os
from fastapi.testclient import TestClient

from lap_gateway.server import create_app


def _client(monkeypatch) -> TestClient:
    # Tests shouldn't depend on local gateway keys.
    monkeypatch.setenv("LAP_ALLOW_EPHEMERAL_SIGNING_KEYS", "1")
    return TestClient(create_app())

def test_stats_requires_auth_by_default_in_prod(monkeypatch):
    monkeypatch.setenv("LAP_ENV", "prod")
    # Ensure no explicit override env var.
    monkeypatch.delenv("LAP_STATS_REQUIRE_AUTH", raising=False)
    monkeypatch.delenv("LAP_STATS_TOKEN", raising=False)

    client = _client(monkeypatch)
    r = client.get("/v1/stats")
    # Should deny without token.
    assert r.status_code in (401, 403)


def test_stats_allows_when_explicitly_disabled(monkeypatch):
    monkeypatch.setenv("LAP_ENV", "prod")
    monkeypatch.setenv("LAP_STATS_REQUIRE_AUTH", "0")

    client = _client(monkeypatch)
    r = client.get("/v1/stats")
    assert r.status_code == 200
