import os
import subprocess
import sys
from pathlib import Path

def test_anchor_cli_required_push_failure_exits_cleanly(tmp_path):
    # Use a known-good pack
    pack = Path("spec/golden_packs/golden_pack_basic.zip")
    out = tmp_path / "anchors.jsonl"
    # Port 9 is typically discard; on localhost it should refuse. We just need a guaranteed failure.
    cmd = [sys.executable, "-m", "lap_cli", "anchor", str(pack), "--out", str(out), "--push", "http://127.0.0.1:9", "--required"]
    p = subprocess.run(cmd, capture_output=True, text=True)
    assert p.returncode == 2, p.stdout + "\n" + p.stderr
    assert "ERROR: transparency push failed:" in p.stderr
    # Should not dump a Python traceback
    assert "Traceback (most recent call last)" not in p.stderr
    # The file may still be written locally; that's OK.
    assert out.exists()
