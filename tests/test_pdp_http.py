import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from lap_gateway.crypto import create_key_pair
from lap_gateway.server import LAPGateway, GatewayStore


class _PDPHandler(BaseHTTPRequestHandler):
    # Class-level decision to return.
    decision = {"outcome": "approve", "tier": "T0_ROUTINE", "reason": "HTTP_PDP_OK"}
    last_body = None

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        _PDPHandler.last_body = body

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(_PDPHandler.decision).encode("utf-8"))

    def log_message(self, format, *args):  # noqa: A003
        # Silence noisy test logs.
        return


@pytest.fixture
def pdp_server():
    httpd = HTTPServer(("127.0.0.1", 0), _PDPHandler)
    host, port = httpd.server_address
    url = f"http://{host}:{port}/v1/decision"

    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield url
    finally:
        httpd.shutdown()
        httpd.server_close()
        t.join(timeout=2)


@pytest.mark.asyncio
async def test_gateway_uses_http_pdp(monkeypatch, tmp_path, pdp_server):
    # Configure gateway to use HTTP PDP.
    monkeypatch.setenv("PDP_MODE", "http")
    monkeypatch.setenv("PDP_URL", pdp_server)
    monkeypatch.setenv("PDP_TIMEOUT_SECONDS", "2")
    monkeypatch.setenv("PDP_HTTP_INPUT_MODE", "opa")

    store = GatewayStore(db_path=str(tmp_path / "gateway.db"))
    gw = LAPGateway(gateway_id="gw_pdp", signing_key=create_key_pair("gw_pdp_key"), store=store)

    evidence = {
        "action_id": "ACT_HTTP_PDP_001",
        "description": (
            "This is a test action intended to validate that the LAP gateway can obtain "
            "decisions from an external HTTP PDP. The request should be sent to the stub "
            "server, and the resulting decision should be reflected in the gateway response."
        ),
        "timestamp_utc": "2026-01-13T00:00:00Z",
        "irreversibility": {"score": 0.05, "reversibility_plan": "No changes are made."},
        "outcome_delta": {},
        "necessity_confidence": 0.9,
        "provenance": {"test": True},
        "alternatives": [],
    }

    res = await gw.evaluate_action(evidence=evidence, agent_id="agent", session_id="", caller_authenticated=False)

    assert res["outcome"] == "approve"
    assert res["tier"] == "T0_ROUTINE"
    assert res["reason"] == "HTTP_PDP_OK"

    # Verify request body shape is OPA-compatible: {"input": evidence}
    body = _PDPHandler.last_body
    assert body is not None
    decoded = json.loads(body.decode("utf-8"))
    assert "input" in decoded
    assert decoded["input"]["action_id"] == "ACT_HTTP_PDP_001"
