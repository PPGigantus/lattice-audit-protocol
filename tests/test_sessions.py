from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import lap_gateway.server as srv


def test_gateway_store_session_roundtrip(tmp_path, monkeypatch):
    db = tmp_path / "gw.db"
    store = srv.GatewayStore(db_path=str(db))

    t0 = datetime(2026, 1, 12, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(srv, "_now_utc", lambda: t0)

    sid, exp = store.create_session(agent_id="agent_001", ttl_seconds=3600)
    assert sid.startswith("sess_")
    assert isinstance(exp, str)

    assert store.validate_session(sid, "agent_001") is True
    assert store.validate_session(sid, "other_agent") is False


def test_gateway_store_session_expiry(tmp_path, monkeypatch):
    db = tmp_path / "gw.db"
    store = srv.GatewayStore(db_path=str(db))

    t0 = datetime(2026, 1, 12, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(srv, "_now_utc", lambda: t0)

    sid, _ = store.create_session(agent_id="agent_001", ttl_seconds=60)
    assert store.validate_session(sid, "agent_001") is True

    # Advance time beyond TTL
    t1 = t0 + timedelta(seconds=61)
    monkeypatch.setattr(srv, "_now_utc", lambda: t1)

    # purge should remove it; validate should fail closed
    store.purge_expired_sessions()
    assert store.validate_session(sid, "agent_001") is False
