import sqlite3

import pytest

from lap_gateway.server import GatewayStore
from lap_gateway.lockdown import StorageLockdownError


def test_storage_lockdown_trips_on_operational_error(tmp_path, monkeypatch):
    db_path = tmp_path / "gw.db"

    monkeypatch.setenv("LAP_DB_CONNECT_TIMEOUT_SECONDS", "0.01")
    monkeypatch.setenv("LAP_DB_FAILURE_THRESHOLD", "1")
    monkeypatch.setenv("LAP_DB_LOCKDOWN_SECONDS", "60")

    store = GatewayStore(db_path=str(db_path))

    # Simulate a storage-layer failure (e.g., DB locked/busy) without relying on
    # platform-specific WAL locking behavior.
    import lap_gateway.server as server_mod

    def _boom(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(server_mod.sqlite3, "connect", _boom)

    with pytest.raises(sqlite3.OperationalError):
        store.get_budget_usage("some_jti")

    # Once tripped, all subsequent store ops fail-closed during the lockdown window.
    with pytest.raises(StorageLockdownError):
        store.get_budget_usage("some_jti")
