from contextlib import contextmanager

from lap_gateway.server import GatewayStore


def test_nonce_reuse_denies_fast_without_db(tmp_path):
    db_path = tmp_path / "gw.db"
    store = GatewayStore(db_path=str(db_path))

    ok, reason = store.check_and_record_nonce("jti1", "n1")
    assert ok, reason

    @contextmanager
    def boom(*args, **kwargs):
        raise AssertionError("DB should not be called on fast nonce deny")
        yield  # pragma: no cover

    # Replace _db with a boom context manager; the second call should deny-fast.
    store._db = boom  # type: ignore

    ok2, reason2 = store.check_and_record_nonce("jti1", "n1")
    assert not ok2
    assert "NONCE_REUSED" in reason2


def test_counter_replay_denies_fast_without_db(tmp_path):
    db_path = tmp_path / "gw.db"
    store = GatewayStore(db_path=str(db_path))

    ok, reason = store.check_and_update_counter("jti2", 1)
    assert ok, reason

    @contextmanager
    def boom(*args, **kwargs):
        raise AssertionError("DB should not be called on fast counter deny")
        yield  # pragma: no cover

    store._db = boom  # type: ignore

    ok2, reason2 = store.check_and_update_counter("jti2", 1)
    assert not ok2
    assert "COUNTER_NOT_MONOTONIC" in reason2


def test_nonce_scoped_per_token(tmp_path):
    db_path = tmp_path / "gw.db"
    store = GatewayStore(db_path=str(db_path))

    ok, _ = store.check_and_record_nonce("jtiA", "n")
    assert ok
    ok2, _ = store.check_and_record_nonce("jtiB", "n")
    assert ok2
