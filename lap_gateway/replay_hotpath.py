"""In-memory replay protection hot path (deny-fast).

This cache is only used to reject obvious replays without a DB round trip.
The durable store remains authoritative for acceptance. Entries are written
*only after* durable store success.

Env:
- LAP_REPLAY_HOTPATH_TTL_SECONDS (default: 3600)
- LAP_REPLAY_HOTPATH_MAX_ITEMS (default: 50000)
"""

from __future__ import annotations

import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class ReplayHotPathConfig:
    ttl_seconds: int = 3600
    max_items: int = 50000

    @classmethod
    def from_env(cls) -> "ReplayHotPathConfig":
        ttl = int(os.getenv("LAP_REPLAY_HOTPATH_TTL_SECONDS", str(cls.ttl_seconds)))
        max_items = int(os.getenv("LAP_REPLAY_HOTPATH_MAX_ITEMS", str(cls.max_items)))
        # Clamp to sensible bounds
        ttl = max(1, min(ttl, 7 * 24 * 3600))
        max_items = max(100, min(max_items, 5_000_000))
        return cls(ttl_seconds=ttl, max_items=max_items)


class ReplayHotPath:
    def __init__(self, config: Optional[ReplayHotPathConfig] = None):
        self.config = config or ReplayHotPathConfig.from_env()
        self._lock = threading.Lock()
        # nonce_key -> expires_at
        self._nonces: "OrderedDict[str, float]" = OrderedDict()
        # jti -> (last_counter, expires_at)
        self._counters: "OrderedDict[str, Tuple[int, float]]" = OrderedDict()

    def _now(self) -> float:
        return time.monotonic()

    def _purge_nonces(self, now: float) -> None:
        # OrderedDict oldest-first
        while self._nonces:
            k, exp = next(iter(self._nonces.items()))
            if exp > now:
                break
            self._nonces.popitem(last=False)

    def _purge_counters(self, now: float) -> None:
        while self._counters:
            k, (val, exp) = next(iter(self._counters.items()))
            if exp > now:
                break
            self._counters.popitem(last=False)

    def _evict_if_needed(self) -> None:
        max_items = self.config.max_items
        # Split budget roughly across the two caches
        max_n = max_items // 2
        max_c = max_items - max_n
        while len(self._nonces) > max_n:
            self._nonces.popitem(last=False)
        while len(self._counters) > max_c:
            self._counters.popitem(last=False)

    @staticmethod
    def _nonce_key(jti: str, nonce: str) -> str:
        return f"{jti}:{nonce}"

    def nonce_seen(self, jti: str, nonce: str) -> bool:
        now = self._now()
        key = self._nonce_key(jti, nonce)
        with self._lock:
            self._purge_nonces(now)
            exp = self._nonces.get(key)
            if exp is None:
                return False
            if exp <= now:
                # expired
                self._nonces.pop(key, None)
                return False
            # touch
            self._nonces.move_to_end(key)
            return True

    def record_nonce(self, jti: str, nonce: str) -> None:
        now = self._now()
        exp = now + self.config.ttl_seconds
        key = self._nonce_key(jti, nonce)
        with self._lock:
            self._purge_nonces(now)
            self._nonces[key] = exp
            self._nonces.move_to_end(key)
            self._evict_if_needed()

    def counter_last(self, jti: str) -> Optional[int]:
        now = self._now()
        with self._lock:
            self._purge_counters(now)
            item = self._counters.get(jti)
            if item is None:
                return None
            last, exp = item
            if exp <= now:
                self._counters.pop(jti, None)
                return None
            self._counters.move_to_end(jti)
            return last

    def deny_if_counter_not_monotonic(self, jti: str, counter: int) -> Tuple[bool, Optional[int]]:
        last = self.counter_last(jti)
        if last is None:
            return False, None
        return counter <= last, last

    def record_counter(self, jti: str, counter: int) -> None:
        now = self._now()
        exp = now + self.config.ttl_seconds
        with self._lock:
            self._purge_counters(now)
            self._counters[jti] = (counter, exp)
            self._counters.move_to_end(jti)
            self._evict_if_needed()
