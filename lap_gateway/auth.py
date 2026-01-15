"""Caller authentication helpers for LAP Gateway.

This provides a simple API-key based identity mechanism so that caller identity
is not client-controlled. If no mapping is configured, callers may still supply
X-Agent-Id but it is treated as unauthenticated.

Env vars:
  - LAP_API_KEYS_JSON: JSON dict mapping api_key -> agent_id
  - LAP_API_KEYS_FILE: path to a JSON file with the same mapping
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

ENV_API_KEYS_JSON = "LAP_API_KEYS_JSON"
ENV_API_KEYS_FILE = "LAP_API_KEYS_FILE"


@dataclass(frozen=True)
class AuthContext:
    """Resolved caller identity context."""

    agent_id: Optional[str]
    authenticated: bool
    error: Optional[str] = None




@dataclass(frozen=True)
class ApiKeyAuth:
    """API key authentication config."""

    api_key_to_agent: Dict[str, str]
    configured: bool = False
    config_error: Optional[str] = None

    @classmethod
    def load_from_env(cls) -> "ApiKeyAuth":
        """Load API key mapping from env/file.

        Security note: if configuration is *present* but malformed, we return an
        instance with config_error set so callers can fail closed.
        """
        mapping: Dict[str, str] = {}
        configured = False
        config_error: Optional[str] = None

        raw_json = os.getenv(ENV_API_KEYS_JSON)
        file_path = os.getenv(ENV_API_KEYS_FILE)

        if raw_json or file_path:
            configured = True

        try:
            if raw_json:
                data = json.loads(raw_json)
                if not isinstance(data, dict):
                    raise ValueError("LAP_API_KEYS_JSON must be a JSON object")
                mapping = {str(k): str(v) for k, v in data.items()}
            elif file_path:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if not isinstance(data, dict):
                    raise ValueError("LAP_API_KEYS_FILE must contain a JSON object")
                mapping = {str(k): str(v) for k, v in data.items()}
        except Exception:
            # Fail closed at usage time if mapping was intended but malformed.
            config_error = "API_KEY_CONFIG_INVALID"
            mapping = {}

        return cls(api_key_to_agent=mapping, configured=configured, config_error=config_error)

    def enabled(self) -> bool:
        # Enabled means the deployer intentionally configured API key auth.
        return self.configured

    def resolve_identity(
        self,
        api_key: Optional[str],
        claimed_agent_id: Optional[str] = None,
        require_if_enabled: bool = True,
    ) -> Tuple[Optional[str], Optional[str]]:
        """Resolve caller identity.

        Returns (agent_id, error). If error is not None, the request should be
        rejected.
        """
        if self.config_error:
            return None, self.config_error

        if not self.enabled():
            # Backwards compatible mode (unauthenticated)
            return claimed_agent_id, None

        if not api_key:
            if require_if_enabled:
                return None, "API_KEY_REQUIRED"
            return claimed_agent_id, None

        agent_id = self.api_key_to_agent.get(api_key)
        if not agent_id:
            return None, "API_KEY_INVALID"

        if claimed_agent_id and claimed_agent_id != agent_id:
            return None, "AGENT_ID_MISMATCH"

        return agent_id, None

    def resolve_context(
        self,
        api_key: Optional[str],
        claimed_agent_id: Optional[str] = None,
        require_if_enabled: bool = True,
    ) -> AuthContext:
        """Resolve caller identity plus authenticated status.

        This is a convenience wrapper around resolve_identity, but it also
        reports whether the agent_id was derived from a configured API-key map.
        """
        # Use the same resolution logic as resolve_identity so mismatches are
        # rejected consistently across endpoints.
        agent_id, err = self.resolve_identity(
            api_key=api_key,
            claimed_agent_id=claimed_agent_id,
            require_if_enabled=require_if_enabled,
        )
        if err:
            return AuthContext(agent_id=None, authenticated=False, error=err)

        authenticated = bool(self.enabled() and api_key and agent_id and self.api_key_to_agent.get(api_key) == agent_id)
        return AuthContext(agent_id=agent_id, authenticated=authenticated, error=None)


