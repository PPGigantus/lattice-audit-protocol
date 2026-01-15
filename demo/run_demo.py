#!/usr/bin/env python3
"""
PR-010 Adoption Kit Demo (end-to-end)

Goal: a reader can:
  - run the gateway + tool demo locally
  - produce audit pack zips
  - verify them offline

This demo intentionally performs *two* tool calls safely by minting
two separate capability tokens (one per tool call), so each token remains
single-use in practice and avoids budget/reservation edge cases.

No external network calls.
Standard library only for HTTP requests.

Run:
  python demo/run_demo.py

Outputs:
  demo/out/audit_pack_demo_call1.zip
  demo/out/audit_pack_demo_call2.zip
"""
from __future__ import annotations

import atexit
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import urllib.request
import urllib.error


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "demo" / "out"

GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = int(os.getenv("LAP_DEMO_GATEWAY_PORT", "8000"))
TOOL_PORT = int(os.getenv("LAP_DEMO_TOOL_PORT", "9000"))

API_KEY = "demo-key-1"
AGENT_ID = "demo_agent_001"

# Deterministic demo signing seed (32 bytes => 64 hex chars)
# This is a DEMO-ONLY key. Do not reuse in production.
DEMO_SIGNING_SEED_HEX = "2f" * 32
DEMO_SIGNING_KEY_ID = "demo_gateway_k1"


def _http_json(
    method: str,
    url: str,
    payload: Optional[Dict[str, Any]] = None,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 5.0,
) -> Tuple[int, Dict[str, Any]]:
    data = None
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            obj = json.loads(raw) if raw else {}
        except Exception:
            obj = {"error": raw[:500]}
        return e.code, obj


def _wait_for_health(base_url: str, timeout_seconds: float = 10.0) -> None:
    deadline = time.time() + timeout_seconds
    last_err = ""
    while time.time() < deadline:
        try:
            code, obj = _http_json("GET", f"{base_url}/v1/health", None, timeout=1.0)
            if code == 200 and obj.get("status") == "healthy":
                return
            last_err = f"health={code} {obj}"
        except Exception as e:
            last_err = str(e)
        time.sleep(0.2)
    raise RuntimeError(f"Gateway not healthy: {last_err}")


def _start_process(argv: list[str], env: Dict[str, str], cwd: Path) -> subprocess.Popen:
    # Use a quiet-ish process; send stdout/stderr to pipes so demo remains clean.
    return subprocess.Popen(
        argv,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def _terminate_process(p: subprocess.Popen, name: str) -> None:
    if p.poll() is not None:
        return
    try:
        p.send_signal(signal.SIGINT)
    except Exception:
        pass
    try:
        p.wait(timeout=2.0)
        return
    except Exception:
        pass
    try:
        p.terminate()
    except Exception:
        pass
    try:
        p.wait(timeout=2.0)
        return
    except Exception:
        pass
    try:
        p.kill()
    except Exception:
        pass


def _read_tail(p: subprocess.Popen, max_lines: int = 30) -> str:
    if p.stdout is None:
        return ""
    try:
        lines = []
        while True:
            line = p.stdout.readline()
            if not line:
                break
            lines.append(line.rstrip("\n"))
            if len(lines) > max_lines:
                lines = lines[-max_lines:]
        return "\n".join(lines)
    except Exception:
        return ""


def _make_evidence(action_id: str, timestamp_utc: str, *, irr_score: float) -> Dict[str, Any]:
    return {
        "action_id": action_id,
        "description": (
            "Demo action for LAP adoption kit. "
            "This description is intentionally long enough to pass evidence-quality minimums."
        ),
        "timestamp_utc": timestamp_utc,
        "irreversibility": {
            "score": irr_score,
            "reversibility_plan": "Demo is reversible: local processes and files can be deleted.",
        },
        "outcome_delta": {"summary": "Local demo; no external side effects."},
        "necessity_confidence": 0.90,
        "novelty_loss_estimate": 0.0,
        "novelty_method": "none",
        "suffering_risk_estimate": 0.10,
        "suffering_method": "heuristic",
        "provenance": {"demo": True},
        "alternatives": [
            {"description": "Do nothing; skip demo tool call."},
        ],
        "attestations": [],
    }


def _decision_from_eval(resp: Dict[str, Any]) -> Dict[str, Any]:
    # Decision hash in this codebase is computed from:
    #   [action_id, evidence_hash, outcome, tier, reason]
    return {
        "outcome": resp.get("outcome", ""),
        "tier": resp.get("tier", ""),
        "reason": resp.get("reason", ""),
    }


def main() -> int:
    # Clean output dir for determinism
    if OUT_DIR.exists():
        shutil.rmtree(OUT_DIR)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    base_url = f"http://{GATEWAY_HOST}:{GATEWAY_PORT}"

    # Start tool server
    tool_env = os.environ.copy()
    tool_env["TOOL_PORT"] = str(TOOL_PORT)
    tool_proc = _start_process([sys.executable, str(ROOT / "demo" / "tool" / "tool_server.py")], tool_env, ROOT)

    # Start gateway server
    gw_env = os.environ.copy()
    gw_env["LAP_DB_PATH"] = str(OUT_DIR / "gateway_demo.db")
    gw_env["LAP_HTTP_TOOL_URL"] = f"http://{GATEWAY_HOST}:{TOOL_PORT}"
    gw_env["LAP_API_KEYS_JSON"] = json.dumps({API_KEY: AGENT_ID})
    gw_env["LAP_GATEWAY_SIGNING_KEY_ID"] = DEMO_SIGNING_KEY_ID
    gw_env["LAP_GATEWAY_SIGNING_KEY"] = DEMO_SIGNING_SEED_HEX
    # Keep logs readable in demo environments
    gw_env.setdefault("LAP_LOG_LEVEL", "warning")

    gw_proc = _start_process(
        [sys.executable, "-m", "lap_gateway.server", "--host", GATEWAY_HOST, "--port", str(GATEWAY_PORT)],
        gw_env,
        ROOT,
    )

    # Ensure cleanup
    def _cleanup() -> None:
        _terminate_process(gw_proc, "gateway")
        _terminate_process(tool_proc, "tool")

    atexit.register(_cleanup)

    # Wait for gateway
    _wait_for_health(base_url)

    headers_base = {
        "X-Api-Key": API_KEY,
        "X-Agent-Id": AGENT_ID,
    }

    # Create session (required for T2/T3)
    code, sess = _http_json("POST", f"{base_url}/v1/session/new", {"ttl_seconds": 3600}, headers=headers_base)
    if code != 200:
        tail = _read_tail(gw_proc)
        raise RuntimeError(f"Session creation failed: HTTP {code} {sess}\n{tail}")
    session_id = str(sess.get("session_id", "")).strip()
    if not session_id:
        raise RuntimeError(f"Session creation returned no session_id: {sess}")

    # Build and run two tool calls (each action evaluated independently => two tokens => safe)
    calls = [
        ("DEMO_ACTION_001", "2026-01-13T00:00:00Z", 0.35, {"message": "hello from call1"}),
        ("DEMO_ACTION_002", "2026-01-13T00:00:10Z", 0.35, {"message": "hello from call2"}),
    ]

    # Import helpers locally (no extra deps)
    sys.path.insert(0, str(ROOT))
    from lap_gateway.audit_pack import AuditPackBuilder
    from lap_gateway.tokens import CapabilityToken
    from lap_gateway.crypto import Ed25519KeyPair

    # Compute public key from deterministic seed for offline verification
    demo_key = Ed25519KeyPair.from_seed(bytes.fromhex(DEMO_SIGNING_SEED_HEX), key_id=DEMO_SIGNING_KEY_ID)
    trusted_keys = {DEMO_SIGNING_KEY_ID: demo_key.public_key_hex}

    created_packs: list[str] = []

    counter = 1
    for idx, (action_id, ts, irr, tool_params) in enumerate(calls, start=1):
        evidence = _make_evidence(action_id, ts, irr_score=irr)
        eval_headers = dict(headers_base)
        eval_headers["X-Session-Id"] = session_id

        code, eval_resp = _http_json("POST", f"{base_url}/v1/evaluate", evidence, headers=eval_headers)
        if code != 200:
            tail = _read_tail(gw_proc)
            raise RuntimeError(f"Evaluate failed for {action_id}: HTTP {code} {eval_resp}\n{tail}")

        if eval_resp.get("outcome") != "approve" or not eval_resp.get("capability_token"):
            raise RuntimeError(f"Demo expected approve+token, got: {eval_resp}")

        token_compact = str(eval_resp["capability_token"])
        token_obj = CapabilityToken.from_compact(token_compact).to_dict()
        decision = _decision_from_eval(eval_resp)

        # Invoke HTTP tool through gateway
        nonce = f"demo-nonce-{idx}"
        invoke_payload = {
            "tool_name": "http",
            # T2 capability tokens default to allowed_ops=["execute"]
            "operation": "execute",
            "params": tool_params,
            "capability_token": token_compact,
            "nonce": nonce,
            # counter is optional for T2; omit to keep minimal
        }
        code, inv_resp = _http_json(
            "POST",
            f"{base_url}/v1/tools/http/invoke",
            invoke_payload,
            headers=eval_headers,
            timeout=10.0,
        )
        if code != 200:
            tail = _read_tail(gw_proc)
            raise RuntimeError(f"Invoke failed for {action_id}: HTTP {code} {inv_resp}\n{tail}")
        if not inv_resp.get("success", False):
            raise RuntimeError(f"Tool invocation reported failure: {inv_resp}")

        receipt = inv_resp.get("receipt") or {}
        if not receipt:
            raise RuntimeError(f"No receipt returned: {inv_resp}")

        # Build + write audit pack zip
        builder = AuditPackBuilder(gateway_id="demo_gateway", protocol_version="2.0.0")
        contents = builder.build_pack(
            action_id=action_id,
            evidence=evidence,
            decision=decision,
            token=token_obj,
            receipts=[receipt],
            trusted_keys=trusted_keys,
            invocations=[{
                "receipt_id": str(receipt.get("receipt_id", "")),
                "params": tool_params,
                "result": inv_resp.get("result"),
                "response_envelope": {
                    "success": bool(inv_resp.get("success", False)),
                    "result": inv_resp.get("result"),
                    "error": inv_resp.get("error"),
                },
            }],
        )
        out_zip = str(OUT_DIR / f"audit_pack_demo_call{idx}.zip")
        builder.write_pack(contents, out_zip)
        created_packs.append(out_zip)

        counter += 1

    print("\nDemo complete. Created audit packs:")
    for p in created_packs:
        print(f"  - {p}")

    print("\nVerify offline:")
    for idx in range(1, 3):
        print(f"  python lap_cli.py schema-validate demo/out/audit_pack_demo_call{idx}.zip")
        print(f"  python lap_verify.py audit-pack demo/out/audit_pack_demo_call{idx}.zip")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
