"""lap_gateway.pdp

Policy Decision Point (PDP) client interface.

PR-007 introduces a small abstraction so the gateway (PEP) can obtain
decisions from either:

* a built-in evaluator (existing LAP logic), or
* an HTTP PDP (e.g., OPA / custom policy service).

The HTTP adapter is intentionally generic:

Request body (OPA-compatible by default):
    {"input": <evidence dict>}

Response body:
    * either a decision object directly (must contain outcome/tier/reason)
    * or OPA-style: {"result": <decision object>}

No OPA URL paths are hard-coded; PDP_URL must be a fully-qualified endpoint.

Fail-closed behavior:
    Any HTTP/network/parse/schema mismatch returns a deny decision.
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Any, Dict, Optional, Protocol


class PDPClient(Protocol):
    """A minimal PDP interface.

    Returned value must conform to the existing decision schema:
      - outcome: str
      - tier: str
      - reason: str
    """

    def evaluate(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        ...


@dataclass
class BuiltinPDPClient:
    """PDP client that delegates to the gateway's built-in evaluation logic."""

    gateway: Any

    def evaluate(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        try:
            # Mirror prior behavior: if the protocol engine is enabled and available,
            # use it; otherwise fall back to the simple evaluator.
            if getattr(self.gateway, "lap_protocol", None):
                outcome, tier, reason = self.gateway._evaluate_with_lap_protocol(evidence)
            else:
                outcome, tier, reason = self.gateway._simple_evaluate(evidence)
            return {
                "outcome": str(outcome),
                "tier": str(tier),
                "reason": str(reason),
            }
        except Exception as e:
            # Fail closed.
            return {
                "outcome": "deny",
                "tier": str(getattr(self.gateway, "_estimate_tier", lambda _e: "T2_HIGH_STAKES")(evidence)),
                "reason": f"PDP_BUILTIN_ERROR: {type(e).__name__}: {e}",
            }


@dataclass
class HttpPDPClient:
    """HTTP-based PDP client.

    By default, sends an OPA-compatible JSON payload: {"input": evidence}.
    Set PDP_HTTP_INPUT_MODE=raw to send evidence directly.
    """

    url: str
    timeout_seconds: float = 5.0
    input_mode: str = "opa"  # 'opa' or 'raw'

    def evaluate(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        # Prepare request body
        mode = (self.input_mode or "opa").strip().lower()
        body_obj: Any
        if mode == "raw":
            body_obj = evidence
        else:
            body_obj = {"input": evidence}

        body = json.dumps(body_obj).encode("utf-8")
        req = urllib.request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                resp_bytes = resp.read()
            decoded = json.loads(resp_bytes.decode("utf-8"))
        except urllib.error.HTTPError as e:
            return {
                "outcome": "deny",
                "tier": "T2_HIGH_STAKES",
                "reason": f"PDP_HTTP_ERROR: HTTP {getattr(e, 'code', '???')}",
            }
        except Exception as e:
            return {
                "outcome": "deny",
                "tier": "T2_HIGH_STAKES",
                "reason": f"PDP_HTTP_ERROR: {type(e).__name__}: {e}",
            }

        # Accept either direct decision object or OPA-style {"result": {...}}
        decision = decoded
        if isinstance(decoded, dict) and "result" in decoded:
            decision = decoded.get("result")

        if not isinstance(decision, dict):
            return {
                "outcome": "deny",
                "tier": "T2_HIGH_STAKES",
                "reason": "PDP_HTTP_INVALID_RESPONSE: expected decision object",
            }

        # Required fields
        outcome = decision.get("outcome")
        tier = decision.get("tier")
        reason = decision.get("reason")
        if not isinstance(outcome, str) or not isinstance(tier, str) or not isinstance(reason, str):
            return {
                "outcome": "deny",
                "tier": "T2_HIGH_STAKES",
                "reason": "PDP_HTTP_INVALID_RESPONSE: missing outcome/tier/reason",
            }

        return decision


def build_pdp_client_from_env(gateway: Any) -> PDPClient:
    """Build the PDP client from env vars.

    Env:
      PDP_MODE: builtin|http (default builtin)
      PDP_URL: required if PDP_MODE=http
      PDP_TIMEOUT_SECONDS: optional, float
      PDP_HTTP_INPUT_MODE: optional, opa|raw (default opa)
    """

    mode = os.getenv("PDP_MODE", "builtin").strip().lower() or "builtin"
    if mode == "http":
        url = os.getenv("PDP_URL", "").strip()
        if not url:
            # Fail closed by creating a client that always denies.
            return HttpPDPClient(url="http://invalid.invalid/", timeout_seconds=0.01)
        timeout_s = float(os.getenv("PDP_TIMEOUT_SECONDS", "5") or "5")
        input_mode = os.getenv("PDP_HTTP_INPUT_MODE", "opa")
        return HttpPDPClient(url=url, timeout_seconds=timeout_s, input_mode=input_mode)
    return BuiltinPDPClient(gateway=gateway)
