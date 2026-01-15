from __future__ import annotations

import json
import tempfile
import zipfile
from pathlib import Path

import lap_verify


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _extract_golden_pack(tmpdir: Path) -> Path:
    repo = _repo_root()
    zp = repo / "spec" / "golden_packs" / "golden_pack_basic.zip"
    assert zp.exists(), f"missing golden pack: {zp}"
    with zipfile.ZipFile(zp, "r") as zf:
        zf.extractall(tmpdir)
    return tmpdir


def test_profile_bronze_vectors_and_golden_pack_ok() -> None:
    repo = _repo_root()
    vectors_dir = repo / "spec" / "test_vectors"
    ok, msgs = lap_verify.verify_profile(
        "bronze",
        str(vectors_dir),
        repo_root=repo,
        skip_signatures=False,
    )
    # If this fails, print the first failing message to make debugging obvious.
    if not ok:
        first_bad = next((m for m in msgs if not m.ok), None)
        raise AssertionError(f"bronze profile failed: {first_bad}")


def test_profile_silver_attestation_ok() -> None:
    repo = _repo_root()
    att = repo / "spec" / "profile_attestations" / "silver_example.json"
    ok, msgs = lap_verify.verify_profile("silver", str(att), repo_root=repo)
    if not ok:
        first_bad = next((m for m in msgs if not m.ok), None)
        raise AssertionError(f"silver profile failed: {first_bad}")


def test_mutation_reorder_keys_preserves_verification() -> None:
    with tempfile.TemporaryDirectory() as td:
        pack_dir = _extract_golden_pack(Path(td))

        # Rewrite evidence.json with a different key order / whitespace.
        ev_path = pack_dir / "evidence.json"
        evidence = json.loads(ev_path.read_text(encoding="utf-8"))
        ev_path.write_text(json.dumps(evidence, indent=2, sort_keys=False) + "\n", encoding="utf-8")

        ok, msgs = lap_verify.verify_audit_pack_dir(pack_dir)
        if not ok:
            first_bad = next((m for m in msgs if not m.ok), None)
            raise AssertionError(f"expected ok after reorder; failed: {first_bad}")


def test_mutation_evidence_semantic_change_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as td:
        pack_dir = _extract_golden_pack(Path(td))

        ev_path = pack_dir / "evidence.json"
        evidence = json.loads(ev_path.read_text(encoding="utf-8"))
        # Semantic change: should break evidence_hash vs manifest.
        evidence["purpose"] = str(evidence.get("purpose", "")) + " (tampered)"
        ev_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        ok, msgs = lap_verify.verify_audit_pack_dir(pack_dir)
        assert not ok
        assert any(m.code == "EVIDENCE_HASH_MISMATCH" for m in msgs)


def test_mutation_token_kid_unknown_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as td:
        pack_dir = _extract_golden_pack(Path(td))

        token_path = pack_dir / "token.json"
        tok = json.loads(token_path.read_text(encoding="utf-8"))
        tok["key_id"] = "unknown_key_id"
        token_path.write_text(json.dumps(tok, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        ok, msgs = lap_verify.verify_audit_pack_dir(pack_dir)
        assert not ok
        assert any(m.code in {"TOKEN_SIG_INVALID", "TOKEN_PARSE_ERROR"} for m in msgs)


def test_mutation_receipt_signature_tamper_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as td:
        pack_dir = _extract_golden_pack(Path(td))

        receipts_path = pack_dir / "receipts.json"
        receipts = json.loads(receipts_path.read_text(encoding="utf-8"))
        assert isinstance(receipts, list) and receipts, "golden pack receipts missing"
        sig = receipts[0].get("signature", "")
        assert isinstance(sig, str) and sig, "receipt signature missing"

        # Flip a base64 character while staying base64-valid.
        mid = len(sig) // 2
        ch = sig[mid]
        flip = "A" if ch != "A" else "B"
        receipts[0]["signature"] = sig[:mid] + flip + sig[mid + 1 :]
        receipts_path.write_text(json.dumps(receipts, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        ok, _ = lap_verify.verify_audit_pack_dir(pack_dir)
        assert not ok
