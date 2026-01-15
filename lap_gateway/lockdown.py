"""Circuit breaker + lockdown utilities.

Goal
----
Fail-closed under storage degradation.

The gateway relies on storage for replay prevention, budgets, decision state,
and audit logging. If storage becomes slow, locked, or unresponsive (e.g. DDoS
amplifies WAL contention), we must transition to a stricter operating mode.

This module provides a small circuit breaker that can be used around SQLite
(or other) operations.

Notes
-----
This is not a substitute for stronger state backends (e.g., Redis/Lua or HSM),
but it provides an immediate "fail-closed" invariant for deployments that
still rely on SQLite.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional


class StorageLockdownError(RuntimeError):
    """Raised when the system is in LOCKDOWN due to degraded storage."""


@dataclass
class CircuitBreakerConfig:
    """Configuration for DbCircuitBreaker.

    Environment variables:
    - LAP_DB_LATENCY_THRESHOLD_MS: trip immediately on ops slower than this.
    - LAP_DB_FAILURE_THRESHOLD: number of failures required to trip.
    - LAP_DB_LOCKDOWN_SECONDS: duration of lockdown window.
    - LAP_DB_CONNECT_TIMEOUT_SECONDS: sqlite connect timeout.
    - LAP_DB_ERROR_STRICT: if '1', treat any OperationalError as failure.
    """

    latency_threshold_ms: int = 250
    failure_threshold: int = 2
    lockdown_seconds: int = 30
    connect_timeout_seconds: float = 5.0
    error_strict: bool = True

    @classmethod
    def from_env(cls) -> "CircuitBreakerConfig":
        def _get_int(name: str, default: int) -> int:
            try:
                return int(os.getenv(name, str(default)).strip())
            except Exception:
                return default

        def _get_float(name: str, default: float) -> float:
            try:
                return float(os.getenv(name, str(default)).strip())
            except Exception:
                return default

        latency = _get_int("LAP_DB_LATENCY_THRESHOLD_MS", cls.latency_threshold_ms)
        failures = _get_int("LAP_DB_FAILURE_THRESHOLD", cls.failure_threshold)
        lockdown = _get_int("LAP_DB_LOCKDOWN_SECONDS", cls.lockdown_seconds)
        timeout = _get_float("LAP_DB_CONNECT_TIMEOUT_SECONDS", cls.connect_timeout_seconds)
        strict = os.getenv("LAP_DB_ERROR_STRICT", "1").strip() not in ("0", "false", "False")

        # Clamp
        if latency < 0:
            latency = cls.latency_threshold_ms
        if failures < 1:
            failures = 1
        if lockdown < 1:
            lockdown = 1
        if timeout <= 0:
            timeout = 0.01

        return cls(
            latency_threshold_ms=latency,
            failure_threshold=failures,
            lockdown_seconds=lockdown,
            connect_timeout_seconds=timeout,
            error_strict=strict,
        )


class DbCircuitBreaker:
    """A simple circuit breaker for DB operations."""

    def __init__(self, config: Optional[CircuitBreakerConfig] = None):
        self.config = config or CircuitBreakerConfig.from_env()
        self._failure_count = 0
        self._lockdown_until_monotonic: float = 0.0

    def is_lockdown_active(self) -> bool:
        return time.monotonic() < self._lockdown_until_monotonic

    def raise_if_lockdown(self) -> None:
        if self.is_lockdown_active():
            raise StorageLockdownError("LOCKDOWN_ACTIVE")

    def _trip(self) -> None:
        self._lockdown_until_monotonic = time.monotonic() + float(self.config.lockdown_seconds)
        # Keep failure_count at threshold to avoid immediate decay confusion.
        self._failure_count = self.config.failure_threshold

    def record_success(self) -> None:
        # Decay failures slowly on success.
        if self._failure_count > 0:
            self._failure_count -= 1

    def record_latency(self, elapsed_ms: float) -> None:
        if elapsed_ms >= float(self.config.latency_threshold_ms):
            # Treat as a failure signal and trip immediately.
            self._failure_count += 1
            self._trip()

    def record_failure(self, exc: Optional[BaseException] = None) -> None:
        self._failure_count += 1
        if self._failure_count >= self.config.failure_threshold:
            self._trip()

    def should_treat_operational_error_as_failure(self, message: str) -> bool:
        if self.config.error_strict:
            return True
        msg = (message or "").lower()
        # SQLite common transient strings
        return ("database is locked" in msg) or ("database is busy" in msg) or ("locked" in msg and "database" in msg)
