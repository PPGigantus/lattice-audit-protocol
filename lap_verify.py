"""lap_verify: Offline verifier for LAP audit artifacts.

This CLI is intended to turn LAP into an "adversarial laboratory":
it verifies exported audit packs without trusting the gateway database.

Supported inputs:
  - An extracted audit pack directory
  - A .zip audit pack created by lap_gateway.audit_pack.AuditPackBuilder

Verification checks:
  1) Evidence hash matches manifest
  2) Decision hash binds (action_id, evidence_hash, outcome, tier, reason)
  3) External approval signature (optional)
  4) Capability token signature (optional)
  5) Receipt signatures and chain integrity (optional)
  6) Receipt hash commitments to params/result/response envelopes, when
     the pack provides the corresponding objects (optional)
  7) Tamper-evident audit log verification (separate subcommand)

Security note: if you run with --skip-signatures, only hashes are checked.
"""

from __future__ import annotations

import argparse
import json
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _safe_hash_encode(components: List[Any]) -> bytes:
    out = b""
    for c in components:
        b = str(c).encode("utf-8")
        out += len(b).to_bytes(8, "big") + b
    return out


def _canon(obj: Any, *, version: str = "v1") -> str:
    """Canonical JSON used for hash commitments.

    Default is v1 for backwards compatibility with existing artifacts.
    Newer artifacts may specify v2 explicitly via manifest/vector settings.
    """

    # Keep this in sync with the published spec (spec/CANONICAL_JSON.md).
    from lap_gateway.crypto import canonical_json_dumps

    return canonical_json_dumps(obj, version=version)


@dataclass
class VerifyMessage:
    ok: bool
    code: str
    detail: str


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _build_keystore(trusted_keys: Dict[str, Any], *, legacy_verify: bool = False):
    from lap_gateway.crypto import TrustedKeyStore

    store = TrustedKeyStore.from_config(trusted_keys or {})
    if legacy_verify:
        store.legacy_verify = True
    return store




def _verify_signature_with_info(key_store, key_id: str, payload: bytes, signature: bytes, *, signed_at_utc: Optional[str] = None, legacy_verify: Optional[bool] = None) -> Tuple[bool, Dict[str, Any]]:
    """Verify a signature and return (ok, info).

    If the underlying key store supports verify_signature_detailed, `info` may
    include lifecycle warnings such as time-bounded revocations.
    """
    if hasattr(key_store, "verify_signature_detailed"):
        ok, info = key_store.verify_signature_detailed(
            key_id,
            payload,
            signature,
            signed_at_utc=signed_at_utc,
            legacy_verify=legacy_verify,
        )
        return bool(ok), info if isinstance(info, dict) else {}
    ok = key_store.verify_signature(key_id, payload, signature, signed_at_utc=signed_at_utc, legacy_verify=legacy_verify)
    return bool(ok), {}


def verify_audit_pack_dir(
    pack_dir: Path,
    *,
    skip_signatures: bool = False,
    require_invocations_for_hash_checks: bool = False,
    trusted_keys_path: Optional[str] = None,
    legacy_verify: bool = False,
) -> Tuple[bool, List[VerifyMessage]]:
    """Verify an extracted audit pack directory."""

    msgs: List[VerifyMessage] = []

    manifest_path = pack_dir / "manifest.json"
    if not manifest_path.exists():
        return False, [VerifyMessage(False, "MISSING_MANIFEST", "manifest.json not found")]

    manifest = _load_json(manifest_path)
    action_id = str(manifest.get("action_id", ""))
    evidence_hash_expected = str(manifest.get("evidence_hash", ""))
    decision_hash_expected = str(manifest.get("decision_hash", ""))
    canon_ver = str(manifest.get("canonical_json_version", "v1") or "v1")
    receipt_profile = str(manifest.get("receipt_profile", "v1") or "v1").lower().strip()

    trusted_keys: Dict[str, Any] = {}
    if trusted_keys_path:
        trusted_keys = _load_json(Path(trusted_keys_path))
    elif (pack_dir / "trusted_keys.json").exists():
        trusted_keys = _load_json(pack_dir / "trusted_keys.json")
    key_store = _build_keystore(trusted_keys, legacy_verify=legacy_verify)

    # 1) Evidence hash
    evidence_path = pack_dir / "evidence.json"
    if not evidence_path.exists():
        msgs.append(VerifyMessage(False, "MISSING_EVIDENCE", "evidence.json not found"))
        return False, msgs
    evidence_obj = _load_json(evidence_path)
    evidence_canon = _canon(evidence_obj, version=canon_ver)
    evidence_hash_actual = _sha256_hex(evidence_canon.encode("utf-8"))
    if evidence_hash_actual != evidence_hash_expected:
        msgs.append(
            VerifyMessage(
                False,
                "EVIDENCE_HASH_MISMATCH",
                f"expected {evidence_hash_expected[:16]}..., got {evidence_hash_actual[:16]}...",
            )
        )
    else:
        msgs.append(VerifyMessage(True, "EVIDENCE_HASH_OK", f"{evidence_hash_actual[:16]}..."))

    # 2) Decision hash
    decision_path = pack_dir / "decision.json"
    if not decision_path.exists():
        msgs.append(VerifyMessage(False, "MISSING_DECISION", "decision.json not found"))
        return False, msgs
    decision_obj = _load_json(decision_path)
    decision_components = [
        action_id,
        evidence_hash_expected,
        decision_obj.get("outcome", ""),
        decision_obj.get("tier", ""),
        decision_obj.get("reason", ""),
    ]
    decision_hash_actual = _sha256_hex(_safe_hash_encode(decision_components))
    if decision_hash_actual != decision_hash_expected:
        msgs.append(
            VerifyMessage(
                False,
                "DECISION_HASH_MISMATCH",
                f"expected {decision_hash_expected[:16]}..., got {decision_hash_actual[:16]}...",
            )
        )
    else:
        msgs.append(VerifyMessage(True, "DECISION_HASH_OK", f"{decision_hash_actual[:16]}..."))

    # 3) External approval (optional)
    approval_path = pack_dir / "external_approval.json"
    if approval_path.exists():
        try:
            from lap_gateway.crypto import Ed25519ExternalApproval

            approval = Ed25519ExternalApproval.from_dict(_load_json(approval_path))
            if approval.action_id != action_id or approval.evidence_hash != evidence_hash_expected:
                msgs.append(
                    VerifyMessage(
                        False,
                        "APPROVAL_BINDING_MISMATCH",
                        "approval action_id/evidence_hash does not match manifest",
                    )
                )
            elif skip_signatures:
                msgs.append(VerifyMessage(True, "APPROVAL_SIG_SKIPPED", "--skip-signatures"))
            else:
                payload = approval.compute_signature_payload()
                ok_sig, info = _verify_signature_with_info(
                    key_store,
                    approval.key_id,
                    payload,
                    approval.signature,
                    signed_at_utc=approval.reviewed_at_utc or None,
                    legacy_verify=legacy_verify,
                )
                if ok_sig:
                    msgs.append(VerifyMessage(True, "APPROVAL_SIG_OK", f"key_id={approval.key_id}"))
                    if info.get("warning") == "key_revoked_effective_later":
                        msgs.append(
                            VerifyMessage(
                                True,
                                "APPROVAL_SIG_OK_KEY_REVOKED",
                                f"key_id={approval.key_id} revoked_at_utc={info.get('revoked_at_utc','')}",
                            )
                        )
                else:
                    msgs.append(VerifyMessage(False, "APPROVAL_SIG_INVALID", f"key_id={approval.key_id}"))
        except Exception as e:
            msgs.append(VerifyMessage(False, "APPROVAL_PARSE_ERROR", str(e)))
    else:
        msgs.append(VerifyMessage(True, "APPROVAL_NOT_PRESENT", "optional"))

    # 4) Token (optional)
    token_path = pack_dir / "token.json"
    token_obj: Optional[Dict[str, Any]] = None
    token_jti: Optional[str] = None
    token_sid: Optional[str] = None
    if token_path.exists():
        try:
            from lap_gateway.tokens import CapabilityToken

            token_obj = _load_json(token_path)
            token = CapabilityToken.from_dict(token_obj)
            token_jti = token.jti
            token_sid = token.sid or None
            binding_ok = (
                token.action_id == action_id
                and token.evidence_hash == evidence_hash_expected
                and token.decision_hash == decision_hash_expected
            )
            if not binding_ok:
                msgs.append(VerifyMessage(False, "TOKEN_BINDING_MISMATCH", "token not bound to manifest"))
            elif skip_signatures:
                msgs.append(VerifyMessage(True, "TOKEN_SIG_SKIPPED", "--skip-signatures"))
            else:
                payload = token.compute_signature_payload()
                ok_sig, info = _verify_signature_with_info(
                    key_store,
                    token.key_id,
                    payload,
                    token.signature,
                    signed_at_utc=token.iat or None,
                    legacy_verify=legacy_verify,
                )
                if ok_sig:
                    msgs.append(VerifyMessage(True, "TOKEN_SIG_OK", f"key_id={token.key_id}"))
                    if info.get("warning") == "key_revoked_effective_later":
                        msgs.append(
                            VerifyMessage(
                                True,
                                "TOKEN_SIG_OK_KEY_REVOKED",
                                f"key_id={token.key_id} revoked_at_utc={info.get('revoked_at_utc','')}",
                            )
                        )
                else:
                    msgs.append(VerifyMessage(False, "TOKEN_SIG_INVALID", f"key_id={token.key_id}"))
        except Exception as e:
            msgs.append(VerifyMessage(False, "TOKEN_PARSE_ERROR", str(e)))
    else:
        msgs.append(VerifyMessage(True, "TOKEN_NOT_PRESENT", "optional"))

    # Optional invocations data (for verifying params/result/response hash commitments)
    invocations: Dict[str, Dict[str, Any]] = {}
    inv_path = pack_dir / "invocations.json"
    if inv_path.exists():
        try:
            inv_list = _load_json(inv_path)
            if isinstance(inv_list, list):
                for row in inv_list:
                    rid = str(row.get("receipt_id", ""))
                    if rid:
                        invocations[rid] = row
            msgs.append(VerifyMessage(True, "INVOCATIONS_PRESENT", f"{len(invocations)} record(s)"))
        except Exception as e:
            msgs.append(VerifyMessage(False, "INVOCATIONS_PARSE_ERROR", str(e)))
    else:
        if require_invocations_for_hash_checks:
            msgs.append(VerifyMessage(False, "INVOCATIONS_REQUIRED", "invocations.json not found"))
        else:
            msgs.append(VerifyMessage(True, "INVOCATIONS_NOT_PRESENT", "hash-commit checks skipped"))

    # 5) Receipts (optional)
    receipts_path = pack_dir / "receipts.json"
    if receipts_path.exists():
        try:
            from lap_gateway.receipts import (
                ToolInvocationReceipt,
                compute_decision_binding,
                compute_decision_binding_v1,
            )

            receipts_list = _load_json(receipts_path)
            if not receipts_list:
                msgs.append(VerifyMessage(True, "NO_RECEIPTS", "optional"))
            else:
                prev_hash = ""
                all_ok = True
                for i, rdict in enumerate(receipts_list):
                    receipt = ToolInvocationReceipt.from_dict(rdict)

                    # Binding checks
                    if receipt.action_id != action_id or receipt.evidence_hash != evidence_hash_expected or receipt.decision_hash != decision_hash_expected:
                        all_ok = False
                        msgs.append(
                            VerifyMessage(
                                False,
                                "RECEIPT_BINDING_MISMATCH",
                                f"idx={i} receipt_id={receipt.receipt_id}",
                            )
                        )

                    # Token binding if token present
                    if token_jti is not None and receipt.token_jti != token_jti:
                        all_ok = False
                        msgs.append(
                            VerifyMessage(
                                False,
                                "RECEIPT_TOKEN_MISMATCH",
                                f"idx={i} expected {token_jti}, got {receipt.token_jti}",
                            )
                        )

                    # Session binding if token present
                    if token_sid is not None:
                        if not receipt.sid or receipt.sid != token_sid:
                            all_ok = False
                            msgs.append(
                                VerifyMessage(
                                    False,
                                    "RECEIPT_SESSION_MISMATCH",
                                    f"idx={i} receipt_id={receipt.receipt_id}",
                                )
                            )

                    # Decision binding hardening (anti-splice / anti-mix-and-match)
                    if not receipt.decision_binding:
                        if not legacy_verify:
                            all_ok = False
                            msgs.append(
                                VerifyMessage(
                                    False,
                                    "DECISION_BINDING_MISSING",
                                    f"idx={i} receipt_id={receipt.receipt_id}",
                                )
                            )
                    else:
                        # Prefer hardened binding (v2)
                        expected_db = compute_decision_binding(
                            decision_hash=receipt.decision_hash,
                            token_jti=receipt.token_jti,
                            action_id=receipt.action_id,
                            sid=receipt.sid or (token_sid or ""),
                            tool_name=receipt.tool_name,
                            operation=receipt.operation,
                            params_hash=receipt.params_hash,
                            prev_receipt_hash=receipt.prev_receipt_hash,
                            evidence_hash=receipt.evidence_hash,
                        )
                        if receipt.decision_binding != expected_db:
                            # Legacy fallback (v1) is only allowed in legacy mode
                            expected_v1 = compute_decision_binding_v1(
                                decision_hash=receipt.decision_hash,
                                token_jti=receipt.token_jti,
                                action_id=receipt.action_id,
                                tool_name=receipt.tool_name,
                                params_hash=receipt.params_hash,
                            )
                            if not (legacy_verify and receipt.decision_binding == expected_v1):
                                all_ok = False
                                msgs.append(
                                    VerifyMessage(
                                        False,
                                        "DECISION_BINDING_MISMATCH",
                                        f"idx={i} receipt_id={receipt.receipt_id}",
                                    )
                                )

                    # Chain check
                    if receipt.prev_receipt_hash != prev_hash:
                        all_ok = False
                        msgs.append(
                            VerifyMessage(
                                False,
                                "RECEIPT_CHAIN_BROKEN",
                                f"idx={i} expected prev={prev_hash[:16]}..., got {receipt.prev_receipt_hash[:16]}...",
                            )
                        )

                    # Signature check
                    if skip_signatures:
                        sig_ok = True
                    else:
                        payload = receipt.compute_signature_payload()
                        sig_ok, info = _verify_signature_with_info(
                            key_store,
                            receipt.key_id,
                            payload,
                            receipt.signature,
                            signed_at_utc=(receipt.completed_at_utc or receipt.invoked_at_utc or None),
                            legacy_verify=legacy_verify,
                        )
                        if sig_ok and info.get("warning") == "key_revoked_effective_later":
                            msgs.append(
                                VerifyMessage(
                                    True,
                                    "RECEIPT_SIG_OK_KEY_REVOKED",
                                    f"idx={i} receipt_id={receipt.receipt_id} key_id={receipt.key_id} revoked_at_utc={info.get('revoked_at_utc','')}",
                                )
                            )
                    if not sig_ok:
                        all_ok = False
                        msgs.append(
                            VerifyMessage(
                                False,
                                "RECEIPT_SIG_INVALID",
                                f"idx={i} receipt_id={receipt.receipt_id} key_id={receipt.key_id}",
                            )
                        )

                    # Receipt hash integrity (do not trust embedded receipt_hash)
                    computed_hash = receipt.compute_receipt_hash()
                    embedded_hash = str(rdict.get("receipt_hash", ""))
                    if embedded_hash and embedded_hash != computed_hash:
                        all_ok = False
                        msgs.append(
                            VerifyMessage(
                                False,
                                "RECEIPT_HASH_MISMATCH",
                                f"idx={i} receipt_id={receipt.receipt_id}",
                            )
                        )

                    # Hash-commit checks against invocations, if provided
                    inv = invocations.get(receipt.receipt_id)
                    if inv:
                        if "params" in inv:
                            # Hash-commit is over a params envelope to prevent tool/op mix-and-match.
                            params_env = {
                                "tool_name": receipt.tool_name,
                                "operation": receipt.operation,
                                "params": inv["params"],
                            }
                            ph = _sha256_hex(_canon(params_env, version="v1").encode("utf-8"))
                            if ph != receipt.params_hash:
                                all_ok = False
                                msgs.append(
                                    VerifyMessage(
                                        False,
                                        "PARAMS_HASH_MISMATCH",
                                        f"idx={i} receipt_id={receipt.receipt_id}",
                                    )
                                )
                        if "result" in inv:
                            rh = _sha256_hex(_canon(inv["result"], version="v1").encode("utf-8"))
                            if rh != receipt.result_hash:
                                all_ok = False
                                msgs.append(
                                    VerifyMessage(
                                        False,
                                        "RESULT_HASH_MISMATCH",
                                        f"idx={i} receipt_id={receipt.receipt_id}",
                                    )
                                )
                        if "response_envelope" in inv:
                            eh = _sha256_hex(_canon(inv["response_envelope"], version="v1").encode("utf-8"))
                            if eh != receipt.response_hash:
                                all_ok = False
                                msgs.append(
                                    VerifyMessage(
                                        False,
                                        "RESPONSE_HASH_MISMATCH",
                                        f"idx={i} receipt_id={receipt.receipt_id}",
                                    )
                                )

                    prev_hash = computed_hash

                msgs.append(
                    VerifyMessage(
                        all_ok,
                        "RECEIPTS_OK" if all_ok else "RECEIPTS_FAILED",
                        f"count={len(receipts_list)}",
                    )
                )
        except Exception as e:
            msgs.append(VerifyMessage(False, "RECEIPTS_PARSE_ERROR", str(e)))
    else:
        msgs.append(VerifyMessage(True, "RECEIPTS_NOT_PRESENT", "optional"))

    ok = all(m.ok for m in msgs)
    return ok, msgs


def verify_audit_pack_path(
    path: str,
    *,
    skip_signatures: bool = False,
    require_invocations_for_hash_checks: bool = False,
    trusted_keys_path: Optional[str] = None,
    legacy_verify: bool = False,
) -> Tuple[bool, List[VerifyMessage]]:
    p = Path(path)
    if p.is_dir():
        return verify_audit_pack_dir(
            p,
            skip_signatures=skip_signatures,
            require_invocations_for_hash_checks=require_invocations_for_hash_checks,
            trusted_keys_path=trusted_keys_path,
            legacy_verify=legacy_verify,
        )
    if p.is_file() and p.suffix.lower() == ".zip":
        with tempfile.TemporaryDirectory() as td:
            with zipfile.ZipFile(str(p), "r") as zf:
                zf.extractall(td)
            return verify_audit_pack_dir(
                Path(td),
                skip_signatures=skip_signatures,
                require_invocations_for_hash_checks=require_invocations_for_hash_checks,
                trusted_keys_path=trusted_keys_path,
                legacy_verify=legacy_verify,
            )
    return False, [VerifyMessage(False, "BAD_PATH", f"not a dir or .zip: {path}")]


def verify_audit_log(path: str, trusted_keys_path: Optional[str] = None, *, legacy_verify: bool = False) -> Tuple[bool, str, int]:
    from lap_gateway.audit_log import TamperEvidentAuditLog
    from lap_gateway.crypto import TrustedKeyStore

    keys: Dict[str, Any] = {}
    if trusted_keys_path:
        keys = json.loads(Path(trusted_keys_path).read_text(encoding="utf-8"))
    store = _build_keystore(keys if isinstance(keys, dict) else {}, legacy_verify=legacy_verify)
    return TamperEvidentAuditLog.verify_file(path, store)


def verify_test_vectors_dir(
    vectors_dir: Path,
    *,
    skip_signatures: bool = False,
) -> Tuple[bool, List[VerifyMessage]]:
    """Verify interoperability test vectors.

    The vector format lives in: spec/test_vectors/vectors.json
    """

    msgs: List[VerifyMessage] = []

    vectors_path = vectors_dir / "vectors.json"
    if not vectors_path.exists():
        return False, [VerifyMessage(False, "MISSING_VECTORS", f"not found: {vectors_path}")]

    data = _load_json(vectors_path)
    cases = data.get("cases", []) if isinstance(data, dict) else []
    if not isinstance(cases, list) or not cases:
        return False, [VerifyMessage(False, "BAD_VECTORS", "vectors.json missing cases")]

    for case in cases:
        try:
            name = str(case.get("name", ""))
            ctype = str(case.get("type", ""))
            if not name or not ctype:
                msgs.append(VerifyMessage(False, "VECTOR_BAD_CASE", "missing name/type"))
                continue

            if ctype == "evidence_hash":
                jf = vectors_dir / str(case["input_file"])
                obj = _load_json(jf)
                canon_ver = str(case.get("canonical_json_version", "v1") or "v1")
                got = _sha256_hex(_canon(obj, version=canon_ver).encode("utf-8"))
                exp = str(case["expected"])
                msgs.append(
                    VerifyMessage(got == exp, "VECTOR_EVIDENCE_HASH", f"{name}: {got[:16]}...")
                )

            elif ctype == "decision_hash":
                jf = vectors_dir / str(case["input_file"])
                decision = _load_json(jf)
                action_id = str(case.get("action_id", ""))
                evidence_hash = str(case.get("evidence_hash", ""))
                comps = [
                    action_id,
                    evidence_hash,
                    decision.get("outcome", ""),
                    decision.get("tier", ""),
                    decision.get("reason", ""),
                ]
                got = _sha256_hex(_safe_hash_encode(comps))
                exp = str(case["expected"])
                msgs.append(
                    VerifyMessage(got == exp, "VECTOR_DECISION_HASH", f"{name}: {got[:16]}...")
                )

            elif ctype == "params_hash":
                jf = vectors_dir / str(case["input_file"])
                obj = _load_json(jf)
                canon_ver = str(case.get("canonical_json_version", "v1") or "v1")
                got = _sha256_hex(_canon(obj, version=canon_ver).encode("utf-8"))
                exp = str(case["expected"])
                msgs.append(VerifyMessage(got == exp, "VECTOR_PARAMS_HASH", f"{name}: {got[:16]}..."))

            elif ctype == "token_verify":
                from lap_gateway.tokens import CapabilityToken

                token_file = vectors_dir / str(case["token_file"])
                token = CapabilityToken.from_dict(_load_json(token_file))
                keys = case.get("trusted_keys", {})
                store = _build_keystore(keys if isinstance(keys, dict) else {})
                if skip_signatures:
                    ok = True
                    detail = f"{name}: signature skipped"
                else:
                    # Prefer detailed verification so vectors can assert lifecycle warnings
                    # (e.g., trust-at-event-time revocation semantics).
                    payload = token.compute_signature_payload()
                    ok_sig, info = _verify_signature_with_info(
                        store,
                        token.key_id,
                        payload,
                        token.signature,
                        signed_at_utc=token.iat or None,
                    )
                    ok = bool(ok_sig)

                    exp_warn = case.get("expect_warning")
                    got_warn = info.get("warning") if isinstance(info, dict) else None
                    warn_ok = True
                    if exp_warn is not None:
                        warn_ok = (str(got_warn) == str(exp_warn))
                    ok = bool(ok and warn_ok)

                    if exp_warn is not None:
                        detail = (
                            f"{name}: key_id={token.key_id} warning={got_warn} "
                            f"revoked_at_utc={info.get('revoked_at_utc','')}"
                        )
                    else:
                        detail = f"{name}: key_id={token.key_id}"
                exp_ok = bool(case.get("expect_ok", True))
                msgs.append(VerifyMessage(ok == exp_ok, "VECTOR_TOKEN_VERIFY", detail))

            elif ctype == "receipt_verify":
                from lap_gateway.receipts import ToolInvocationReceipt

                receipt_file = vectors_dir / str(case["receipt_file"])
                rdict = _load_json(receipt_file)
                receipt = ToolInvocationReceipt.from_dict(rdict)
                keys = case.get("trusted_keys", {})
                store = _build_keystore(keys if isinstance(keys, dict) else {})
                if skip_signatures:
                    sig_ok = True
                else:
                    sig_ok = receipt.verify(store)
                got_hash = receipt.compute_receipt_hash()
                exp_hash = str(case.get("expected_receipt_hash", got_hash))
                ok = sig_ok and (got_hash == exp_hash)
                msgs.append(
                    VerifyMessage(ok, "VECTOR_RECEIPT_VERIFY", f"{name}: {got_hash[:16]}...")
                )

            elif ctype == "audit_pack_verify":
                # Verify a full audit pack (.zip or directory) relative to the vectors dir.
                rel = str(case.get("path", ""))
                if not rel:
                    msgs.append(VerifyMessage(False, "VECTOR_BAD_CASE", f"{name}: missing path"))
                    continue
                target = (vectors_dir / rel).resolve()
                ok_pack, pack_msgs = verify_audit_pack_path(
                    target,
                    skip_signatures=skip_signatures,
                    require_invocations_for_hash_checks=bool(case.get("require_invocations", False)),
                )
                exp_ok = bool(case.get("expect_ok", True))
                # Surface only the top failing code for brevity.
                detail = f"{name}: {'ok' if ok_pack else 'fail'}"
                if not ok_pack and pack_msgs:
                    first_bad = next((m for m in pack_msgs if not m.ok), None)
                    if first_bad:
                        detail += f" ({first_bad.code})"
                msgs.append(VerifyMessage(ok_pack == exp_ok, "VECTOR_AUDIT_PACK_VERIFY", detail))

            else:
                msgs.append(VerifyMessage(False, "VECTOR_UNKNOWN_TYPE", f"{name}: {ctype}"))
        except Exception as e:
            msgs.append(VerifyMessage(False, "VECTOR_ERROR", f"{case.get('name','')}: {e}"))

    ok = all(m.ok for m in msgs)
    return ok, msgs


def verify_profile(
    profile: str,
    path: str,
    *,
    skip_signatures: bool = False,
    repo_root: Optional[Path] = None,
) -> Tuple[bool, List[VerifyMessage]]:
    """Verify a compliance profile claim.

    - bronze: validates and verifies a vectors directory or an audit pack
    - silver/gold: validates a profile attestation JSON

    See spec/PROFILES.md.
    """

    repo_root = repo_root or Path(__file__).resolve().parent
    p = Path(path)
    msgs: List[VerifyMessage] = []

    prof = profile.lower().strip()
    if prof not in {"bronze", "silver", "gold"}:
        return False, [VerifyMessage(False, "PROFILE_BAD_NAME", f"unknown profile: {profile}")]

    if prof == "bronze":
        # 1) If passed a directory, treat as vectors dir.
        if p.is_dir():
            ok_vec, vec_msgs = verify_test_vectors_dir(p, skip_signatures=skip_signatures)
            msgs.extend(vec_msgs)

            # Schema-validate all json artifacts in the vectors dir (best-effort).
            try:
                from lap_schema_validate import validate_file
                any_schema_fail = False
                for jf in sorted(p.glob("*.json")):
                    if jf.name == "vectors.json":
                        continue
                    ok_s, smsgs = validate_file(jf)
                    # Only surface failures and a single success marker.
                    if not ok_s:
                        any_schema_fail = True
                        for sm in smsgs:
                            msgs.append(VerifyMessage(False, "SCHEMA_FAIL", f"{jf.name}: {sm.detail}"))
                if not any_schema_fail:
                    msgs.append(VerifyMessage(True, "SCHEMA_OK", "vectors artifacts schema-valid"))
            except Exception as e:
                msgs.append(VerifyMessage(False, "SCHEMA_VALIDATE_ERROR", str(e)))

            # Also verify the default golden pack if it exists.
            golden = repo_root / "spec" / "golden_packs" / "golden_pack_basic.zip"
            if golden.exists():
                ok_pack, pack_msgs = verify_audit_pack_path(
                    str(golden),
                    skip_signatures=skip_signatures,
                    require_invocations_for_hash_checks=True,
                )
                # Add only summary and first failure to avoid noisy output.
                if ok_pack:
                    msgs.append(VerifyMessage(True, "GOLDEN_PACK_OK", golden.name))
                else:
                    first_bad = next((m for m in pack_msgs if not m.ok), None)
                    detail = f"{golden.name}: fail" + (f" ({first_bad.code})" if first_bad else "")
                    msgs.append(VerifyMessage(False, "GOLDEN_PACK_FAIL", detail))
            else:
                msgs.append(VerifyMessage(False, "GOLDEN_PACK_MISSING", "spec/golden_packs/golden_pack_basic.zip"))

            ok_all = all(m.ok for m in msgs)
            return ok_all and ok_vec, msgs

        # 2) If passed a file (zip), treat as an audit pack.
        if p.is_file():
            ok_pack, pack_msgs = verify_audit_pack_path(
                str(p),
                skip_signatures=skip_signatures,
                require_invocations_for_hash_checks=True,
            )
            msgs.extend(pack_msgs)
            try:
                from lap_schema_validate import validate_path

                ok_schema, smsgs = validate_path(p, strict=True)
                for sm in smsgs:
                    if sm.ok:
                        continue
                    msgs.append(VerifyMessage(False, "SCHEMA_FAIL", sm.detail))
                if ok_schema:
                    msgs.append(VerifyMessage(True, "SCHEMA_OK", "audit pack schema-valid"))
            except Exception as e:
                msgs.append(VerifyMessage(False, "SCHEMA_VALIDATE_ERROR", str(e)))
            ok_all = all(m.ok for m in msgs)
            return ok_all and ok_pack, msgs

        return False, [VerifyMessage(False, "PROFILE_BAD_PATH", f"not found: {path}")]

    # silver/gold: attestation
    if not p.is_file():
        return False, [VerifyMessage(False, "PROFILE_BAD_PATH", f"not a file: {path}")]

    try:
        from lap_schema_validate import validate_file

        ok_schema, smsgs = validate_file(p, schema_name="profile_attestation")
        if not ok_schema:
            for sm in smsgs:
                msgs.append(VerifyMessage(False, "SCHEMA_FAIL", sm.detail))
            return False, msgs
        msgs.append(VerifyMessage(True, "SCHEMA_OK", "profile attestation schema-valid"))
    except Exception as e:
        return False, [VerifyMessage(False, "SCHEMA_VALIDATE_ERROR", str(e))]

    data = _load_json(p)
    claimed = str(data.get("profile", "")).lower().strip()
    if claimed != prof:
        msgs.append(VerifyMessage(False, "PROFILE_MISMATCH", f"file claims {claimed}, expected {prof}"))
        return False, msgs

    # Requirement helpers
    def _req(flag: bool, code: str, detail: str):
        msgs.append(VerifyMessage(bool(flag), code, detail))

    enf = data.get("enforcement", {}) or {}
    bnd = data.get("boundary", {}) or {}
    sig = data.get("signing", {}) or {}
    appr = data.get("approvals", {}) or {}

    # Common requirements for silver and gold
    _req(enf.get("tokens") is True, "REQ_TOKENS", "token verification enabled")
    _req(enf.get("replay") is True, "REQ_REPLAY", "replay prevention enabled")
    _req(enf.get("budgets") is True, "REQ_BUDGETS", "budget enforcement enabled")
    _req(enf.get("sessions") is True, "REQ_SESSIONS", "session binding enabled")
    _req(enf.get("receipts") is True, "REQ_RECEIPTS", "signed receipts enabled")
    _req(enf.get("audit_log") is True, "REQ_AUDIT_LOG", "tamper-evident audit log enabled")
    _req(bnd.get("tools_not_directly_reachable") is True, "REQ_TOOL_ISOLATION", "tools not directly reachable by agent")
    _req(bnd.get("tool_credentials_held_by_gateway") is True, "REQ_CREDS", "tool credentials held by gateway only")
    _req(sig.get("keyset") is True, "REQ_KEYSET", "keyset verification enabled")
    _req(sig.get("rotation_supported") is True, "REQ_ROTATION", "rotation supported")

    if prof == "gold":
        _req(bnd.get("agent_egress_restricted") is True, "REQ_EGRESS", "agent egress restricted")
        _req(sig.get("external_signer") is True, "REQ_EXTERNAL_SIGNER", "external signer/HSM in use")
        _req(appr.get("t3_requires_multi_party") is True, "REQ_T3_MPA", "T3 requires multi-party approval")
        _req(appr.get("reviewer_keyset_configured") is True, "REQ_REVIEW_KEYS", "reviewer keyset configured")

    ok_all = all(m.ok for m in msgs)
    return ok_all, msgs


def _print_messages(msgs: List[VerifyMessage]) -> None:
    for m in msgs:
        mark = "✓" if m.ok else "✗"
        print(f"{mark} {m.code}: {m.detail}")


def _emit_json(
    ok: bool,
    command: str,
    messages: Optional[List[VerifyMessage]] = None,
    *,
    extra: Optional[Dict[str, Any]] = None,
    pretty: bool = False,
) -> int:
    """Emit a machine-readable JSON report and return an exit code."""

    payload: Dict[str, Any] = {"ok": bool(ok), "command": command}
    if extra:
        payload.update(extra)
    if messages is not None:
        payload["messages"] = [
            {"ok": bool(m.ok), "code": str(m.code), "detail": str(m.detail)} for m in messages
        ]

    if pretty:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(json.dumps(payload, separators=(",", ":"), sort_keys=True))

    return 0 if ok else 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="lap-verify", description="Offline verifier for LAP audit artifacts")
    parser.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        help="Emit machine-readable JSON output instead of human text",
    )
    parser.add_argument(
        "--pretty",
        dest="json_pretty",
        action="store_true",
        help="Pretty-print JSON output (only with --json)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_pack = sub.add_parser("audit-pack", help="Verify an audit pack directory or .zip")
    p_pack.add_argument("path", help="Path to audit pack dir or .zip")
    p_pack.add_argument("--skip-signatures", action="store_true", help="Skip signature verification")
    p_pack.add_argument(
        "--require-invocations",
        action="store_true",
        help="Fail if invocations.json missing (needed for params/result/response hash checks)",
    )
    p_pack.add_argument("--trusted-keys", help="Path to trusted key registry JSON", default=None)
    p_pack.add_argument(
        "--legacy-verify",
        action="store_true",
        help="Allow verification with keys outside validity windows (legacy mode)",
    )


    p_log = sub.add_parser("audit-log", help="Verify a tamper-evident audit log file")
    p_log.add_argument("path", help="Path to audit log JSONL")
    p_log.add_argument("--trusted-keys", help="Path to trusted_keys.json", default=None)
    p_log.add_argument(
        "--legacy-verify",
        action="store_true",
        help="Allow verification with keys outside validity windows (legacy mode)",
    )

    p_vec = sub.add_parser("vectors", help="Verify interoperability test vectors")
    p_vec.add_argument(
        "path",
        nargs="?",
        default="spec/test_vectors",
        help="Path to a test-vectors directory (default: spec/test_vectors)",
    )
    p_vec.add_argument("--skip-signatures", action="store_true", help="Skip signature verification")

    p_prof = sub.add_parser("profile", help="Verify a compliance profile claim")
    p_prof.add_argument("profile", choices=["bronze", "silver", "gold"], help="Profile name")
    p_prof.add_argument("path", help="Vectors dir, audit pack path, or profile_attestation.json")
    p_prof.add_argument("--skip-signatures", action="store_true", help="Skip signature verification")
    p_prof.add_argument(
        "--repo-root",
        default=None,
        help="Repo root (used to locate spec/golden_packs when verifying bronze vectors)",
    )

    args = parser.parse_args(argv)

    if args.cmd == "audit-pack":
        ok, msgs = verify_audit_pack_path(
            args.path,
            skip_signatures=args.skip_signatures,
            require_invocations_for_hash_checks=args.require_invocations,
            trusted_keys_path=args.trusted_keys,
            legacy_verify=args.legacy_verify,
        )
        if args.json_out:
            return _emit_json(
                ok,
                "audit-pack",
                msgs,
                extra={
                    "path": args.path,
                    "skip_signatures": bool(args.skip_signatures),
                    "require_invocations": bool(args.require_invocations),
                    "legacy_verify": bool(args.legacy_verify),
                },
                pretty=args.json_pretty,
            )
        _print_messages(msgs)
        return 0 if ok else 1

    if args.cmd == "audit-log":
        ok, reason, count = verify_audit_log(args.path, args.trusted_keys, legacy_verify=args.legacy_verify)
        if args.json_out:
            msgs = [VerifyMessage(ok, "AUDIT_LOG_OK" if ok else "AUDIT_LOG_FAIL", f"{reason} (records={count})")]
            return _emit_json(
                ok,
                "audit-log",
                msgs,
                extra={"path": args.path, "records": count, "legacy_verify": bool(args.legacy_verify)},
                pretty=args.json_pretty,
            )
        if ok:
            print(f"✓ AUDIT_LOG_OK: {reason} (records={count})")
            return 0
        print(f"✗ AUDIT_LOG_FAIL: {reason} (records={count})")
        return 1

    if args.cmd == "vectors":
        ok, msgs = verify_test_vectors_dir(Path(args.path), skip_signatures=args.skip_signatures)
        if args.json_out:
            return _emit_json(
                ok,
                "vectors",
                msgs,
                extra={"path": args.path, "skip_signatures": bool(args.skip_signatures)},
                pretty=args.json_pretty,
            )
        _print_messages(msgs)
        return 0 if ok else 1

    if args.cmd == "profile":
        rr = Path(args.repo_root) if args.repo_root else None
        ok, msgs = verify_profile(
            args.profile,
            args.path,
            skip_signatures=args.skip_signatures,
            repo_root=rr,
        )
        if args.json_out:
            return _emit_json(
                ok,
                "profile",
                msgs,
                extra={"profile": args.profile, "path": args.path, "skip_signatures": bool(args.skip_signatures)},
                pretty=args.json_pretty,
            )
        _print_messages(msgs)
        return 0 if ok else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
