"""HTTP Tool Connector (optional).

A minimal connector that lets the LAP Gateway invoke a tool exposed as an HTTP service.

Enable by setting:
- LAP_HTTP_TOOL_URL=http://tool:9000
- LAP_HTTP_TOOL_API_KEY=...   (optional; forwarded as X-Tool-Api-Key)

This connector uses only the standard library (urllib). It's meant as a small
reference implementation for demos and simple deployments.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any, Dict, Optional, Tuple

from .server import ToolConnector


class HttpToolConnector(ToolConnector):
    """Invoke an external tool via HTTP POST."""

    def __init__(self, tool_name: str, base_url: str):
        super().__init__(tool_name)
        self.base_url = base_url.rstrip("/")

    def get_allowed_operations(self):
        return ["invoke", "execute"]

    async def invoke(
        self,
        operation: str,
        params: Dict[str, Any],
        credentials: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Any, Optional[str]]:
        url = f"{self.base_url}/{operation.lstrip('/')}"
        payload = json.dumps({"params": params}).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        if credentials:
            api_key = credentials.get("api_key") or credentials.get("token")
            if api_key:
                headers["X-Tool-Api-Key"] = str(api_key)

        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                try:
                    data = json.loads(body) if body else {}
                except Exception:
                    return False, None, f"TOOL_RESPONSE_NOT_JSON: {body[:200]}"
                ok = bool(data.get("ok", True))
                if not ok:
                    return False, None, str(data.get("error", "TOOL_ERROR"))
                return True, data.get("result", data), None
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return False, None, f"TOOL_HTTP_ERROR_{e.code}: {body[:200]}"
        except Exception as e:
            return False, None, f"TOOL_CONNECT_ERROR: {e}"
