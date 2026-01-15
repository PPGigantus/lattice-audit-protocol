"""Crash-safe monotonic counter journal.

Purpose
-------
Token counters are used for replay resistance (T3 ordering). SQLite provides
atomic commits, but deployments may face:
- abrupt power loss / partial writes to side files
- accidental or malicious rollback of the SQLite DB file (restore from backup)

This journal provides an append-only, fsync'd record of counter advances that:
- survives process restarts
- tolerates a truncated final line after crash
- allows detection of DB rollback (DB counter < journal counter)

Threat model note: if an attacker can replace both the DB and journal, they can
still roll back. Use remote witnesses / attestation for stronger guarantees.
"""

from __future__ import annotations

import json
import os
import time
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional


@dataclass(frozen=True)
class CounterJournalRecord:
    jti: str
    counter: int
    ts_utc: str


class CounterJournal:
    """Append-only journal of (jti, counter) with fsync for durability."""

    def __init__(self, path: str):
        self.path = str(path)
        p = Path(self.path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._max: Dict[str, int] = {}

    @property
    def max_map(self) -> Dict[str, int]:
        # Return a copy to avoid external mutation.
        with self._lock:
            return dict(self._max)

    def max_for(self, jti: str) -> Optional[int]:
        with self._lock:
            return self._max.get(jti)

    def load(self) -> None:
        """Load maxima from journal. Tolerates a truncated final line."""
        with self._lock:
            p = Path(self.path)
            if not p.exists() or p.stat().st_size == 0:
                self._max = {}
                return

            maxima: Dict[str, int] = {}
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        # Likely a truncated tail line after crash; stop and keep maxima.
                        break
                    jti = rec.get("jti")
                    counter = rec.get("counter")
                    if not isinstance(jti, str) or not isinstance(counter, int):
                        continue
                    prev = maxima.get(jti)
                    if prev is None or counter > prev:
                        maxima[jti] = counter
            self._max = maxima

    def append(self, jti: str, counter: int, ts_utc: str) -> None:
        """Append a record and fsync to make it durable."""
        with self._lock:
            rec = {"jti": jti, "counter": int(counter), "ts_utc": ts_utc}
            line = json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n"
            # Ensure directory exists.
            p = Path(self.path)
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            # Update in-memory max.
            prev = self._max.get(jti)
            if prev is None or counter > prev:
                self._max[jti] = counter
