import json
import subprocess
import sys
from pathlib import Path


def _run_verify(argv):
    repo = Path(__file__).resolve().parents[1]
    cmd = [sys.executable, str(repo / "lap_verify.py"), "--json"] + argv
    out = subprocess.check_output(cmd, cwd=repo)
    return json.loads(out.decode("utf-8"))


def test_vectors_json_output_shape():
    payload = _run_verify(["vectors", "spec/test_vectors"])
    assert isinstance(payload, dict)
    assert payload.get("command") == "vectors"
    assert isinstance(payload.get("ok"), bool)
    # messages is a list of objects with ok/code/detail
    msgs = payload.get("messages")
    assert isinstance(msgs, list)
    if msgs:
        m0 = msgs[0]
        assert "ok" in m0 and "code" in m0 and "detail" in m0


def test_audit_pack_json_output_shape(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    pack = repo / "spec" / "golden_packs" / "golden_pack_basic.zip"
    assert pack.exists()
    payload = _run_verify(["audit-pack", str(pack), "--require-invocations"])
    assert payload.get("command") == "audit-pack"
    assert payload.get("path") == str(pack)
    assert isinstance(payload.get("ok"), bool)
