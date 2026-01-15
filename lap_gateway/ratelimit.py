"""Best-effort in-process rate limiting utilities.

This is intentionally simple:
 - No external deps
 - Per-process (not distributed)
 - Designed to reduce accidental/low-effort DoS against sensitive endpoints

For production, prefer an API gateway / reverse proxy rate limiter.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass
class TokenBucket:
    """A basic token bucket limiter.

    capacity: max tokens
    refill_rate_per_sec: tokens added per second
    """

    capacity: float
    refill_rate_per_sec: float
    tokens: float
    last_ts: float

    @classmethod
    def new(cls, capacity: float, refill_rate_per_sec: float) -> "TokenBucket":
        now = time.time()
        return cls(capacity=capacity, refill_rate_per_sec=refill_rate_per_sec, tokens=capacity, last_ts=now)

    def allow(self, cost: float = 1.0) -> bool:
        now = time.time()
        elapsed = max(0.0, now - self.last_ts)
        self.last_ts = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate_per_sec)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


class RateLimiter:
    """Keyed token-bucket rate limiter (per-process)."""

    def __init__(self, capacity: float, refill_rate_per_sec: float, max_keys: int = 20000):
        if capacity <= 0 or refill_rate_per_sec <= 0:
            raise ValueError("capacity and refill_rate_per_sec must be positive")
        self._capacity = float(capacity)
        self._refill = float(refill_rate_per_sec)
        self._max_keys = int(max_keys) if int(max_keys) > 0 else 20000
        self._buckets: Dict[str, TokenBucket] = {}

    def allow(self, key: str, cost: float = 1.0) -> bool:
        if not key:
            key = "_anon"
        bucket = self._buckets.get(key)
        if bucket is None:
            # Prevent unbounded memory growth from high-cardinality keys.
            if len(self._buckets) >= self._max_keys:
                return False
            bucket = TokenBucket.new(self._capacity, self._refill)
            self._buckets[key] = bucket
        return bucket.allow(cost=cost)


def parse_rate_limit(spec: str) -> Tuple[float, float]:
    """Parse a compact rate limit spec like '30/m' or '10/s'.

    Returns (capacity, refill_rate_per_sec).
    """
    s = (spec or "").strip().lower()
    if not s:
        raise ValueError("empty rate limit spec")
    if "/" not in s:
        raise ValueError("invalid rate limit spec; expected like '30/m' or '10/s'")
    num_str, unit = s.split("/", 1)
    n = float(num_str)
    unit = unit.strip()
    if n <= 0:
        raise ValueError("rate must be positive")
    if unit in ("s", "sec", "second", "seconds"):
        per_sec = n
    elif unit in ("m", "min", "minute", "minutes"):
        per_sec = n / 60.0
    elif unit in ("h", "hr", "hour", "hours"):
        per_sec = n / 3600.0
    else:
        raise ValueError(f"unsupported rate unit: {unit}")
    # capacity = n (burst size of one unit)
    return float(n), float(per_sec)
