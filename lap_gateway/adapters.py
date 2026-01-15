"""Integration adapters for complete mediation (PR-023).

These helpers make it hard to bypass LAP by ensuring tool calls flow through
the gateway before execution.

Two common deployment shapes:
1) In-process: the agent and gateway live in the same Python process
2) HTTP: the agent talks to a gateway over HTTP

This module provides:
- `GatewayHTTPClient`: minimal client for /v1 endpoints
- `CompleteMediationRouter`: wrapper that evaluates then invokes tools via gateway
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from .errors import LAPError, lap_error, LAP_E_BAD_REQUEST


@dataclass
class GatewayDecision:
    outcome: str
    tier: str
    reason: str
    action_id: str
    evidence_hash: str
    decision_hash: str
    capability_token: Optional[str]
    requires_mint: bool = False
    constraints: Dict[str, Any] = None


class GatewayHTTPClient:
    """Minimal HTTP client for LAP gateway endpoints."""

    def __init__(self, base_url: str, *, api_key: Optional[str] = None, agent_id: Optional[str] = None, timeout_s: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.agent_id = agent_id
        self.timeout_s = float(timeout_s)

    def _headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            h["X-Api-Key"] = self.api_key
        if self.agent_id:
            h["X-Agent-Id"] = self.agent_id
        return h

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                body = resp.read().decode("utf-8") if resp.readable() else ""
                if body.strip():
                    return json.loads(body)
                return {}
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = {"detail": raw}
            # FastAPI puts the envelope in `detail`
            detail = parsed.get("detail", parsed)
            if isinstance(detail, dict) and "code" in detail:
                raise LAPError(
                    code=str(detail.get("code")),
                    message=str(detail.get("message", "HTTP error")),
                    retryable=bool(detail.get("retryable", False)),
                    http_status=int(e.code),
                    details=dict(detail.get("details", {})),
                )
            raise lap_error(LAP_E_BAD_REQUEST, f"HTTP {e.code}", http_status=int(e.code), body=raw)

    def new_session(self) -> Dict[str, Any]:
        return self._post("/v1/session/new", {"agent_id": self.agent_id or "unknown"})

    def evaluate(self, action: Dict[str, Any]) -> GatewayDecision:
        out = self._post("/v1/evaluate", action)
        return GatewayDecision(
            outcome=str(out.get("outcome")),
            tier=str(out.get("tier")),
            reason=str(out.get("reason")),
            action_id=str(out.get("action_id")),
            evidence_hash=str(out.get("evidence_hash")),
            decision_hash=str(out.get("decision_hash")),
            capability_token=out.get("capability_token"),
            requires_mint=bool(out.get("requires_mint", False)),
            constraints=dict(out.get("constraints", {}) or {}),
        )

    def invoke_tool(
        self,
        tool_name: str,
        *,
        params: Dict[str, Any],
        capability_token: str,
        nonce: Optional[str] = None,
        counter: Optional[int] = None,
        operation: str = "execute",
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "tool_name": tool_name,
            "operation": operation,
            "params": params or {},
            "capability_token": capability_token,
            "nonce": nonce,
            "counter": counter,
        }
        return self._post(f"/v1/tools/{tool_name}/invoke", payload)


class CompleteMediationRouter:
    """Evaluate -> invoke tool via gateway, and execute a local tool map."""

    def __init__(self, gateway: GatewayHTTPClient, tool_map: Dict[str, Callable[[Dict[str, Any]], Any]]):
        self.gateway = gateway
        self.tool_map = tool_map

    def run(
        self,
        tool_name: str,
        *,
        params: Dict[str, Any],
        action: Dict[str, Any],
        nonce: Optional[str] = None,
        counter: Optional[int] = None,
    ) -> Any:
        # 1) Evaluate (policy decision)
        decision = self.gateway.evaluate(action)
        if decision.outcome != "approve" or not decision.capability_token:
            # Denied/escrowed: caller can handle via LAPError or decision fields
            raise lap_error(LAP_E_BAD_REQUEST, f"gateway outcome={decision.outcome}", http_status=403, decision=decision.__dict__)

        # 2) Invoke tool *through gateway* (records receipts)
        self.gateway.invoke_tool(
            tool_name,
            params=params,
            capability_token=decision.capability_token,
            nonce=nonce,
            counter=counter,
        )

        # 3) Execute local tool implementation
        if tool_name not in self.tool_map:
            raise lap_error(LAP_E_BAD_REQUEST, "unknown tool", http_status=404, tool_name=tool_name)

        return self.tool_map[tool_name](params)
