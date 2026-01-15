import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from lap_gateway.transparency import HttpTransparencyLogger


class _CaptureHandler(BaseHTTPRequestHandler):
    captured = []
    captured_headers = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            obj = json.loads(body.decode("utf-8"))
        except Exception:
            obj = {"_raw": body.decode("utf-8", errors="replace")}
        self.__class__.captured.append(obj)
        self.__class__.captured_headers.append(dict(self.headers))
        self.send_response(204)
        self.end_headers()

    def log_message(self, format, *args):
        # silence
        return


def _start_server():
    server = HTTPServer(("127.0.0.1", 0), _CaptureHandler)
    host, port = server.server_address
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, f"http://{host}:{port}/anchors"


def test_http_transparency_push_hash_only():
    _CaptureHandler.captured = []
    server, url = _start_server()
    try:
        logger = HttpTransparencyLogger(url, required=True)
        entry = {"timestamp_utc": "2026-01-14T00:00:00Z", "artifact_type": "receipt", "artifact_hash": "a"*64}
        assert logger.append(entry) is True
        # Wait for handler
        for _ in range(50):
            if _CaptureHandler.captured:
                break
            time.sleep(0.01)
        assert _CaptureHandler.captured == [entry]
    finally:
        server.shutdown()


def test_http_transparency_required_fails_on_unreachable():
    # Choose an unreachable port by binding and closing quickly, or just use a likely-unused high port.
    url = "http://127.0.0.1:9/anchors"  # discard port; should refuse
    logger = HttpTransparencyLogger(url, required=True, max_attempts=2, timeout_s=0.2)
    with pytest.raises(RuntimeError):
        logger.append({"timestamp_utc": "t", "artifact_type": "receipt", "artifact_hash": "b"*64})


def test_http_transparency_nonrequired_returns_false_on_unreachable():
    url = "http://127.0.0.1:9/anchors"
    logger = HttpTransparencyLogger(url, required=False, max_attempts=1, timeout_s=0.2)
    assert logger.append({"timestamp_utc": "t", "artifact_type": "receipt", "artifact_hash": "c"*64}) is False

def test_http_transparency_sets_idempotency_key_header():
    _CaptureHandler.captured = []
    _CaptureHandler.captured_headers = []
    server, url = _start_server()
    try:
        logger = HttpTransparencyLogger(url, required=True)
        entry = {"timestamp_utc": "2026-01-14T00:00:00Z", "artifact_type": "receipt", "artifact_hash": "d"*64}
        assert logger.append(entry) is True

        for _ in range(50):
            if _CaptureHandler.captured_headers:
                break
            time.sleep(0.01)

        assert _CaptureHandler.captured == [entry]
        hdrs = _CaptureHandler.captured_headers[0]
        assert hdrs.get("Idempotency-Key") is not None
        assert logger.last_result is not None
        assert hdrs.get("Idempotency-Key") == logger.last_result.idempotency_key
    finally:
        server.shutdown()


class _SequenceHandler(BaseHTTPRequestHandler):
    # Response codes to emit in sequence for successive POSTs.
    codes = []
    captured = []
    captured_headers = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            obj = json.loads(body.decode("utf-8"))
        except Exception:
            obj = {"_raw": body.decode("utf-8", errors="replace")}
        self.__class__.captured.append(obj)
        self.__class__.captured_headers.append(dict(self.headers))

        code = 204
        if self.__class__.codes:
            code = int(self.__class__.codes.pop(0))
        self.send_response(code)
        self.end_headers()

    def log_message(self, format, *args):
        return


def _start_sequence_server(codes):
    _SequenceHandler.codes = list(codes)
    _SequenceHandler.captured = []
    _SequenceHandler.captured_headers = []
    server = HTTPServer(("127.0.0.1", 0), _SequenceHandler)
    host, port = server.server_address
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, f"http://{host}:{port}/anchors"


def test_http_transparency_treats_409_as_idempotent_success():
    server, url = _start_sequence_server([204, 409])
    try:
        logger = HttpTransparencyLogger(url, required=True, max_attempts=2, timeout_s=0.5)
        entry = {"timestamp_utc": "2026-01-14T00:00:00Z", "artifact_type": "receipt", "artifact_hash": "e"*64}

        assert logger.append(entry) is True
        assert logger.last_result is not None
        assert logger.last_result.ok is True
        assert logger.last_result.code == "ok"

        assert logger.append(entry) is True
        assert logger.last_result is not None
        assert logger.last_result.ok is True
        assert logger.last_result.code == "duplicate"
    finally:
        server.shutdown()


def test_http_transparency_retries_retryable_then_succeeds():
    # 503 is retryable; should retry and eventually succeed.
    server, url = _start_sequence_server([503, 503, 204])
    try:
        logger = HttpTransparencyLogger(url, required=True, max_attempts=5, timeout_s=0.5)
        entry = {"timestamp_utc": "2026-01-14T00:00:00Z", "artifact_type": "receipt", "artifact_hash": "f"*64}
        assert logger.append(entry) is True
        assert logger.last_result is not None
        assert logger.last_result.ok is True
        assert logger.last_result.code == "ok"
        assert logger.last_result.attempts == 3
    finally:
        server.shutdown()


def test_http_transparency_retries_429_then_succeeds():
    # 429 is retryable; should retry and succeed.
    server, url = _start_sequence_server([429, 204])
    try:
        logger = HttpTransparencyLogger(url, required=True, max_attempts=3, timeout_s=0.5)
        entry = {"timestamp_utc": "2026-01-14T00:00:00Z", "artifact_type": "receipt", "artifact_hash": "1"*64}
        assert logger.append(entry) is True
        assert logger.last_result is not None
        assert logger.last_result.ok is True
        assert logger.last_result.code == "ok"
        assert logger.last_result.attempts == 2
    finally:
        server.shutdown()


def test_http_transparency_does_not_retry_permanent_http_when_not_required():
    # 400 is permanent; should not retry. When required=False it should return False.
    server, url = _start_sequence_server([400, 204])
    try:
        logger = HttpTransparencyLogger(url, required=False, max_attempts=3, timeout_s=0.5)
        entry = {"timestamp_utc": "2026-01-14T00:00:00Z", "artifact_type": "receipt", "artifact_hash": "0"*64}
        assert logger.append(entry) is False
        assert logger.last_result is not None
        assert logger.last_result.ok is False
        assert logger.last_result.code == "permanent_http"
        assert logger.last_result.attempts == 1
    finally:
        server.shutdown()
