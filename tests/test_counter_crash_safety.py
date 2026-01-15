import os
import random
import shutil
import sqlite3
import threading
import time

import pytest

from lap_gateway.server import GatewayStore


def _db_last_counter(db_path: str, jti: str) -> int | None:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute("SELECT last_counter FROM token_counters WHERE jti = ?", (jti,))
        row = cur.fetchone()
        if row is None:
            return None
        return int(row[0])
    finally:
        conn.close()


def test_counter_monotonic_across_restart(tmp_path):
    db_path = str(tmp_path / "gw.db")
    jti = "tok_jti_1"

    s1 = GatewayStore(db_path)
    ok, reason = s1.check_and_update_counter(jti, 1)
    assert ok, reason
    ok, reason = s1.check_and_update_counter(jti, 2)
    assert ok, reason

    # Restart: new store instance, same db/journal
    s2 = GatewayStore(db_path)
    ok, reason = s2.check_and_update_counter(jti, 2)
    assert not ok
    assert "LAP_E_COUNTER_NOT_MONOTONIC" in reason

    ok, reason = s2.check_and_update_counter(jti, 3)
    assert ok, reason


def test_counter_concurrency_never_decreases(tmp_path):
    db_path = str(tmp_path / "gw.db")
    jti = "tok_jti_concurrent"

    store = GatewayStore(db_path)
    results: list[tuple[int, bool, str]] = []
    lock = threading.Lock()

    counters = list(range(1, 21))
    random.shuffle(counters)

    def worker(c: int):
        # Stagger to increase interleavings
        time.sleep(random.random() * 0.02)
        ok, reason = store.check_and_update_counter(jti, c)
        with lock:
            results.append((c, ok, reason))

    threads = [threading.Thread(target=worker, args=(c,)) for c in counters]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [c for (c, ok, _r) in results if ok]
    assert len(successes) >= 1
    max_success = max(successes)

    db_last = _db_last_counter(db_path, jti)
    assert db_last == max_success

    # All failures must be <= db_last or be rollback/storage failures
    for c, ok, reason in results:
        if ok:
            continue
        if "LAP_E_COUNTER_ROLLBACK" in reason or "LAP_E_COUNTER_STORAGE" in reason:
            continue
        assert c <= db_last
        assert "LAP_E_COUNTER_NOT_MONOTONIC" in reason


def test_counter_rollback_detected_when_db_behind_journal(tmp_path):
    db = tmp_path / "gw.db"
    db_path = str(db)
    jti = "tok_jti_rb"

    # Establish counter=1 and snapshot DB at that point.
    s = GatewayStore(db_path)
    ok, reason = s.check_and_update_counter(jti, 1)
    assert ok, reason
    snap = tmp_path / "gw_snapshot.db"
    shutil.copyfile(db_path, str(snap))

    # Advance to 3 (journal should have 3).
    ok, reason = s.check_and_update_counter(jti, 2)
    assert ok, reason
    ok, reason = s.check_and_update_counter(jti, 3)
    assert ok, reason

    # Roll back DB to snapshot (counter=1) but leave journal.
    shutil.copyfile(str(snap), db_path)

    s2 = GatewayStore(db_path)
    ok, reason = s2.check_and_update_counter(jti, 2)
    assert not ok
    assert "LAP_E_COUNTER_ROLLBACK" in reason


def test_counter_journal_tolerates_truncated_tail(tmp_path):
    db_path = str(tmp_path / "gw.db")
    jti = "tok_jti_tail"

    s = GatewayStore(db_path)
    ok, reason = s.check_and_update_counter(jti, 1)
    assert ok, reason

    # Corrupt journal with a truncated tail line.
    journal_path = str((tmp_path / "gw").with_suffix(".counters.jsonl"))
    # The journal path is derived from db_path with_suffix:
    journal_path = str((tmp_path / "gw.db").with_suffix(".counters.jsonl"))
    with open(journal_path, "a", encoding="utf-8") as f:
        f.write('{"jti":"tok_jti_tail","counter":')  # truncated

    # Restart should ignore truncated tail and continue.
    s2 = GatewayStore(db_path)
    ok, reason = s2.check_and_update_counter(jti, 2)
    assert ok, reason
