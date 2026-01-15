"""Operational statistics for the gateway.

This module intentionally avoids Prometheus / external dependencies.
It provides lightweight in-memory counters and a snapshot endpoint.

Notes
-----
- Counters reset on process restart.
- Do not treat these as audit evidence. Use receipts/audit packs for evidence.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class _Counters:
    # Decisions
    decisions_total: int = 0
    decisions_by_outcome: Dict[str, int] = field(default_factory=dict)
    decisions_by_tier: Dict[str, int] = field(default_factory=dict)

    # Invocations
    invocations_total: int = 0
    invocations_by_outcome: Dict[str, int] = field(default_factory=dict)  # ok/error/deny
    invocations_by_tool: Dict[str, int] = field(default_factory=dict)

    # Fail-closed signals
    signer_unavailable_total: int = 0
    pdp_errors_total: int = 0
    storage_lockdown_total: int = 0
    rate_limited_total: int = 0
    rate_limited_by_endpoint: Dict[str, int] = field(default_factory=dict)


class OpsStats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._start_monotonic = time.monotonic()
        self._c = _Counters()

    def _inc_map(self, m: Dict[str, int], key: str) -> None:
        m[key] = int(m.get(key, 0)) + 1

    def record_decision(self, tier: str, outcome: str) -> None:
        with self._lock:
            self._c.decisions_total += 1
            self._inc_map(self._c.decisions_by_outcome, outcome or "unknown")
            self._inc_map(self._c.decisions_by_tier, tier or "unknown")

    def record_invocation(self, tool_name: str, outcome: str) -> None:
        with self._lock:
            self._c.invocations_total += 1
            self._inc_map(self._c.invocations_by_outcome, outcome or "unknown")
            self._inc_map(self._c.invocations_by_tool, tool_name or "unknown")

    def record_signer_unavailable(self) -> None:
        with self._lock:
            self._c.signer_unavailable_total += 1

    def record_pdp_error(self) -> None:
        with self._lock:
            self._c.pdp_errors_total += 1

    def record_storage_lockdown(self) -> None:
        with self._lock:
            self._c.storage_lockdown_total += 1

    def record_rate_limited(self, endpoint: str) -> None:
        with self._lock:
            self._c.rate_limited_total += 1
            self._inc_map(self._c.rate_limited_by_endpoint, endpoint or "unknown")

    def snapshot(self, extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
        with self._lock:
            c = self._c
            snap: Dict[str, Any] = {
                "uptime_seconds": int(time.monotonic() - self._start_monotonic),
                "decisions_total": c.decisions_total,
                "decisions_by_outcome": dict(c.decisions_by_outcome),
                "decisions_by_tier": dict(c.decisions_by_tier),
                "invocations_total": c.invocations_total,
                "invocations_by_outcome": dict(c.invocations_by_outcome),
                "invocations_by_tool": dict(c.invocations_by_tool),
                "signer_unavailable_total": c.signer_unavailable_total,
                "pdp_errors_total": c.pdp_errors_total,
                "storage_lockdown_total": c.storage_lockdown_total,
                "rate_limited_total": c.rate_limited_total,
                "rate_limited_by_endpoint": dict(c.rate_limited_by_endpoint),
            }
        if extra:
            snap.update(extra)
        return snap


OPS_STATS = OpsStats()
