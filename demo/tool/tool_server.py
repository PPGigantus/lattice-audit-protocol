import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

TOOL_API_KEY = os.getenv("TOOL_API_KEY", "")

class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        # Support both /invoke and /execute.
        #
        # The gateway's capability tokens commonly constrain allowed_ops to
        # "execute" for T2. Keeping the operation name stable while accepting
        # both endpoints makes the demo less brittle.
        if self.path not in ("/invoke", "/execute"):
            return self._send(404, {"error": "not_found"})

        if TOOL_API_KEY:
            got = self.headers.get("X-Tool-Api-Key", "")
            if got != TOOL_API_KEY:
                return self._send(401, {"error": "invalid_tool_api_key"})

        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            return self._send(400, {"error": "invalid_json"})

        # A minimal tool contract: echo payload and report bytes_out.
        resp = {
            "ok": True,
            "received": data,
            "note": "demo tool response",
        }
        return self._send(200, resp)

    def log_message(self, format, *args):
        # quieter logs
        return

if __name__ == "__main__":
    host = "0.0.0.0"
    port = int(os.getenv("TOOL_PORT", "9000"))
    HTTPServer((host, port), Handler).serve_forever()
