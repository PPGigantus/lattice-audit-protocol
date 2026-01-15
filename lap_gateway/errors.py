"""Stable error taxonomy for LAP.

This module defines machine-readable error codes and a single exception type
used across the gateway, verifier, and integration helpers.

Design goals:
- Stable `code` string suitable for programmatic handling.
- Optional `retryable` flag and `http_status` for transport layers.
- Structured `details` for debugging without parsing messages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


# Canonicalization / hashing
LAP_E_CANON_NON_JSON = "LAP_E_CANON_NON_JSON"
LAP_E_CANON_DEPTH = "LAP_E_CANON_DEPTH"
LAP_E_CANON_NONFINITE = "LAP_E_CANON_NONFINITE"
LAP_E_CANON_KEY_TYPE = "LAP_E_CANON_KEY_TYPE"
LAP_E_CANON_KEY_COLLISION = "LAP_E_CANON_KEY_COLLISION"
LAP_E_CANON_INT_TOO_LARGE = "LAP_E_CANON_INT_TOO_LARGE"

# Gateway / session / auth
LAP_E_AUTH_REQUIRED = "LAP_E_AUTH_REQUIRED"
LAP_E_AGENT_ID_REQUIRED = "LAP_E_AGENT_ID_REQUIRED"
LAP_E_SESSION_MISMATCH = "LAP_E_SESSION_MISMATCH"
LAP_E_RATE_LIMITED = "LAP_E_RATE_LIMITED"
LAP_E_LOCKDOWN_ACTIVE = "LAP_E_LOCKDOWN_ACTIVE"
LAP_E_TOOL_NAME_MISMATCH = "LAP_E_TOOL_NAME_MISMATCH"

# Replay / counters
LAP_E_COUNTER_INVALID = "LAP_E_COUNTER_INVALID"
LAP_E_COUNTER_NOT_MONOTONIC = "LAP_E_COUNTER_NOT_MONOTONIC"
LAP_E_COUNTER_ROLLBACK = "LAP_E_COUNTER_ROLLBACK"
LAP_E_COUNTER_STORAGE = "LAP_E_COUNTER_STORAGE"

# Generic
LAP_E_BAD_REQUEST = "LAP_E_BAD_REQUEST"
LAP_E_INTERNAL = "LAP_E_INTERNAL"

# Transparency / witness
LAP_E_WITNESS_NETWORK = "LAP_E_WITNESS_NETWORK"
LAP_E_WITNESS_RETRYABLE_HTTP = "LAP_E_WITNESS_RETRYABLE_HTTP"
LAP_E_WITNESS_PERMANENT_HTTP = "LAP_E_WITNESS_PERMANENT_HTTP"
LAP_E_WITNESS_DUPLICATE = "LAP_E_WITNESS_DUPLICATE"


@dataclass
class LAPError(Exception):
    """Base LAP exception with stable error code."""

    code: str
    message: str
    retryable: bool = False
    http_status: int = 400
    details: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "retryable": bool(self.retryable),
            "http_status": int(self.http_status),
        }
        if self.details:
            d["details"] = self.details
        return d

    def __str__(self) -> str:
        # Keep message readable; details are available via .as_dict()
        return f"{self.code}: {self.message}"


def lap_error(
    code: str,
    message: str,
    *,
    retryable: bool = False,
    http_status: int = 400,
    **details: Any,
) -> LAPError:
    return LAPError(code=code, message=message, retryable=retryable, http_status=http_status, details=details)
