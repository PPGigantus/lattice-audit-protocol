import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from lap_gateway.crypto import canonical_json_dumps
from lap_gateway.errors import LAPError, LAP_E_CANON_NON_JSON


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def test_canonical_json_v1_stringifies_non_json_types_deterministically():
    dt = datetime(2026, 1, 1, 12, 34, 56, 789000, tzinfo=timezone.utc)
    dec = Decimal("12.3400")
    obj = {"n": dec, "d": dt}

    got = canonical_json_dumps(obj, version="v1")

    # sort_keys=True means "d" comes before "n".
    expected = '{"d":"2026-01-01 12:34:56.789000+00:00","n":"12.3400"}'
    assert got == expected


def test_canonical_json_v2_raises_on_non_json_types():
    dt = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    obj = {"dt": dt}

    with pytest.raises(LAPError) as ei:
        canonical_json_dumps(obj, version="v2")
    assert ei.value.code == LAP_E_CANON_NON_JSON


def test_v2_hash_vectors_match_expected_fixtures():
    repo_root = Path(__file__).resolve().parents[1]
    vectors_dir = repo_root / "spec" / "test_vectors"
    vectors = json.loads((vectors_dir / "vectors.json").read_text(encoding="utf-8"))

    for case in vectors.get("cases", []):
        if case.get("type") not in {"evidence_hash", "params_hash"}:
            continue
        if str(case.get("canonical_json_version", "v1")) != "v2":
            continue

        inp = vectors_dir / str(case["input_file"])
        obj = json.loads(inp.read_text(encoding="utf-8"))
        canon = canonical_json_dumps(obj, version="v2")
        got = sha256_hex(canon)
        assert got == case["expected"], f"Vector {case.get('name')} mismatch"
