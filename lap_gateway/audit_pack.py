"""
LAP Audit Packs (v2.0)

Exportable audit bundles with offline verification.

An audit pack contains everything needed to verify that a specific
action was properly governed by LAP - without trusting the database.

Contents:
- Evidence (canonical JSON + hash)
- Decision record (+ hash)
- External approvals (Ed25519 signed)
- Capability token (+ signature metadata)
- Tool invocation receipts (Ed25519 signed)
- Anchor proof (if anchoring enabled)
- verify.py script
- VERIFY.md instructions
"""

import json
import hashlib
import zipfile
import tempfile
import shutil
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone

from .crypto import (
    Ed25519KeyPair,
    TrustedKeyStore,
    _sha256_hex,
    _safe_hash_encode,
    _now_utc,
    canonical_json_dumps,
)
from .tokens import CapabilityToken
from .receipts import ToolInvocationReceipt, DenialReceipt
from .attestations import receipt_to_attestation_statement
from .dsse import make_envelope, sign_envelope
from .transparency import FileTransparencyLogger, compute_anchor_entries_for_audit_pack_dir


@dataclass
class AuditPackContents:
    """Contents of an audit pack."""
    # Core identifiers
    action_id: str
    evidence_hash: str
    decision_hash: str
    
    # Evidence
    evidence_json: str
    
    # Decision
    decision_json: str
    
    # External approval (if any)
    external_approval_json: Optional[str] = None
    
    # Capability token (if approved)
    token_json: Optional[str] = None
    
    # Receipts
    receipts_json: str = "[]"

    # Optional full invocation objects (for verifying params/result/response hash commitments)
    # Format: list[ {"receipt_id": str, "params": any, "result": any, "response_envelope": dict} ]
    invocations_json: Optional[str] = None
    
    # Anchor proof
    anchor_json: Optional[str] = None
    
    # Trusted public keys used for verification
    trusted_keys_json: str = "{}"
    
    # Metadata
    created_at_utc: str = ""
    gateway_id: str = ""
    protocol_version: str = "2.0.0"
    canonical_json_version: str = "v2"
    receipt_profile: str = "v2"


VERIFY_SCRIPT = '''#!/usr/bin/env python3
"""
LAP Audit Pack Verification Script

Verifies the cryptographic integrity of an audit pack:
1. Evidence hash matches (canonical JSON per manifest)
2. Decision hash matches
3. External approval signature (if present)
4. Capability token signature (if present)
5. Receipt signatures
6. Chain integrity (receipts link correctly)
7. Hash commitments (params/result/response) if invocations.json present

Usage:
    python verify.py [audit_pack_directory] [--allow-no-crypto]

If no directory specified, uses current directory.

Security note:
    This script FAILS CLOSED if `cryptography` is not installed, unless you
    explicitly pass `--allow-no-crypto` (hash-only verification).
"""

import argparse
import json
import hashlib
import base64
import sys
from pathlib import Path


def canonical_json_dumps_v1(obj) -> str:
    """Canonical JSON v1 (legacy/permissive)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def canonical_json_dumps_v2(obj) -> str:
    """Canonical JSON v2 (strict)."""
    # Strict JSON: reject NaN/Infinity so hashes match cross-language verifiers.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def canonical_json_dumps(obj, version: str = "v2") -> str:
    v = str(version or "v2").lower().strip()
    if v in ("v1", "1", "legacy"):
        return canonical_json_dumps_v1(obj)
    if v in ("v2", "2", "strict"):
        return canonical_json_dumps_v2(obj)
    raise ValueError(f"Unknown canonical JSON version: {version!r} (expected v1 or v2)")


# Try to import cryptography for Ed25519
CRYPTO_AVAILABLE = True
CRYPTO_IMPORT_ERROR = None
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception as e:
    CRYPTO_AVAILABLE = False
    CRYPTO_IMPORT_ERROR = str(e)

# Set by CLI flag
ALLOW_NO_CRYPTO = False


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_hash_encode(components: list) -> bytes:
    """Length-prefixed encoding for hash inputs."""
    result = b""
    for component in components:
        encoded = str(component).encode("utf-8")
        length_bytes = len(encoded).to_bytes(8, byteorder="big")
        result += length_bytes + encoded
    return result


def verify_ed25519(public_key_hex: str, message: bytes, signature: bytes) -> bool:
    """Verify Ed25519 signature (fail closed unless explicitly allowed)."""
    if not CRYPTO_AVAILABLE:
        return True if ALLOW_NO_CRYPTO else False
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public_key.verify(signature, message)
        return True
    except Exception as e:
        print(f"  Signature verification error: {e}")
        return False


def load_json_file(path: Path) -> dict:
    """Load JSON file."""
    with open(path) as f:
        return json.load(f)


def verify_evidence(pack_dir: Path, expected_hash: str, canon_version: str) -> tuple:
    """Verify evidence hash."""
    evidence_path = pack_dir / "evidence.json"
    if not evidence_path.exists():
        return False, "evidence.json not found"

    evidence = load_json_file(evidence_path)
    canonical = canonical_json_dumps(evidence, version=canon_version)
    actual_hash = sha256_hex(canonical.encode("utf-8"))

    if actual_hash == expected_hash:
        return True, f"Evidence hash verified ({canon_version}): {actual_hash[:16]}..."
    else:
        return False, f"Evidence hash mismatch ({canon_version}): expected {expected_hash[:16]}..., got {actual_hash[:16]}..."


def verify_decision(pack_dir: Path, expected_hash: str, evidence_hash: str, action_id: str) -> tuple:
    """Verify decision hash."""
    decision_path = pack_dir / "decision.json"
    if not decision_path.exists():
        return False, "decision.json not found"

    decision = load_json_file(decision_path)

    # Decision hash is bound to the audit pack's action_id (from manifest).
    components = [
        action_id,
        evidence_hash,
        decision.get("outcome", ""),
        decision.get("tier", ""),
        decision.get("reason", ""),
    ]
    actual_hash = sha256_hex(safe_hash_encode(components))

    if actual_hash == expected_hash:
        return True, f"Decision hash verified: {actual_hash[:16]}..."
    else:
        return False, f"Decision hash mismatch: expected {expected_hash[:16]}..., got {actual_hash[:16]}..."


def verify_approval(pack_dir: Path, trusted_keys: dict) -> tuple:
    """Verify external approval signature."""
    approval_path = pack_dir / "external_approval.json"
    if not approval_path.exists():
        return True, "No external approval (optional)"

    approval = load_json_file(approval_path)

    key_id = approval.get("key_id", "")
    public_key = trusted_keys.get(key_id)

    if not public_key:
        return False, f"Untrusted key_id: {key_id}"

    # Recompute signature payload
    components = [
        approval["action_id"],
        approval["evidence_hash"],
        approval["reviewer_id"],
        approval["reviewer_type"],
        approval["decision"],
        f"{approval['confidence']:.8f}",
        approval["reasoning"],
        ",".join(sorted(approval.get("conditions", []))),
        approval["reviewed_at_utc"],
    ]
    payload = safe_hash_encode(components)

    signature = base64.b64decode(approval["signature"])

    if verify_ed25519(public_key, payload, signature):
        return True, f"External approval signature verified (key: {key_id})"
    else:
        return False, "External approval signature INVALID"


def verify_token(pack_dir: Path, trusted_keys: dict) -> tuple:
    """Verify capability token signature."""
    token_path = pack_dir / "token.json"
    if not token_path.exists():
        return True, "No capability token (optional)"

    token = load_json_file(token_path)

    key_id = token.get("key_id", "")
    public_key = trusted_keys.get(key_id)

    if not public_key:
        return False, f"Untrusted key_id: {key_id}"

    # Recompute token signature payload
    payload_obj = token.get("payload") or {}
    components = [
        payload_obj.get("sub", ""),
        payload_obj.get("action_id", ""),
        payload_obj.get("evidence_hash", ""),
        payload_obj.get("decision_hash", ""),
        payload_obj.get("tier", ""),
        ",".join(payload_obj.get("allowed_tools", []) or []),
        ",".join(payload_obj.get("allowed_ops", []) or []),
        str(payload_obj.get("budget_tokens", "")),
        str(payload_obj.get("budget_cost", "")),
        str(payload_obj.get("exp", "")),
        payload_obj.get("nonce", ""),
        str(payload_obj.get("counter", "")),
        str(payload_obj.get("nonce_required", False)),
        str(payload_obj.get("counter_required", False)),
        payload_obj.get("params_hash", ""),
        payload_obj.get("sid", ""),
        token.get("signed_at_utc", ""),
    ]
    payload = safe_hash_encode(components)

    signature = base64.b64decode(token.get("signature", ""))

    if verify_ed25519(public_key, payload, signature):
        return True, f"Token signature verified (key: {key_id})"
    else:
        return False, "Token signature INVALID"


def verify_receipts(pack_dir: Path, trusted_keys: dict, token_jti: str | None = None, receipt_profile: str = "v1") -> tuple:
    """Verify receipt signatures and chain integrity.

    Note: this verifier is intentionally lightweight and may lag behind the
    stricter `lap_verify` CLI. For tool-invocation receipts, we prefer using
    the receipt object's own canonical payload/hash methods to avoid drift.
    """
    receipts_path = pack_dir / "receipts.json"
    if not receipts_path.exists():
        return True, "No receipts (optional)"

    receipts = load_json_file(receipts_path)
    if not isinstance(receipts, list):
        return False, "receipts.json must contain a list"

    # Optional invocations commitments
    invocations_path = pack_dir / "invocations.json"
    invocations = {}
    if invocations_path.exists():
        inv_list = load_json_file(invocations_path)
        if isinstance(inv_list, list):
            for item in inv_list:
                rid = str(item.get("receipt_id", ""))
                if rid:
                    invocations[rid] = item

    from lap_gateway.receipts import ToolInvocationReceipt, compute_decision_binding

    prev_hash = ""
    for i, receipt in enumerate(receipts):
        # Determine receipt type (tool invocation vs denial)
        if "tool_name" not in receipt:
            # Denial receipt
            key_id = receipt.get("key_id", "")
            public_key = trusted_keys.get(key_id)
            if not public_key:
                return False, f"Denial receipt {i}: untrusted key_id {key_id}"

            components = [
                receipt["receipt_id"],
                receipt["action_id"],
                receipt["evidence_hash"],
                receipt["decision_hash"],
                receipt["outcome"],
                receipt["tier"],
                receipt["reason"],
                receipt["denied_at_utc"],
            ]
            payload = safe_hash_encode(components)
            signature = base64.b64decode(receipt["signature"])

            if not verify_ed25519(public_key, payload, signature):
                return False, f"Denial receipt {i}: signature INVALID"
            continue

        # Tool invocation receipt
        if token_jti and receipt.get("token_jti") and receipt.get("token_jti") != token_jti:
            return False, f"Receipt {i}: token_jti mismatch"

        rcpt = ToolInvocationReceipt.from_dict(receipt)

        # Chain linking
        if rcpt.prev_receipt_hash != prev_hash:
            return False, f"Receipt {i}: chain broken (expected prev {prev_hash[:16]}...)"

        key_id = receipt.get("key_id", "")
        public_key = trusted_keys.get(key_id)

        if not public_key:
            return False, f"Receipt {i}: untrusted key_id {key_id}"

        # Enforce decision_binding when receipt_profile=v2
        if receipt_profile == "v2":
            if not rcpt.decision_binding:
                return False, f"Receipt {i}: decision_binding missing (receipt_profile=v2)"
            expected_db = compute_decision_binding(
                decision_hash=rcpt.decision_hash,
                token_jti=rcpt.token_jti,
                action_id=rcpt.action_id,
                sid=rcpt.sid,
                tool_name=rcpt.tool_name,
                operation=rcpt.operation,
                params_hash=rcpt.params_hash,
                prev_receipt_hash=rcpt.prev_receipt_hash,
                evidence_hash=rcpt.evidence_hash,
            )
            if rcpt.decision_binding != expected_db:
                return False, f"Receipt {i}: decision_binding mismatch"

        payload = rcpt.compute_signature_payload()
        signature = rcpt.signature

        if not verify_ed25519(public_key, payload, signature):
            return False, f"Receipt {i}: signature INVALID"

        # Recompute receipt hash (do not trust embedded receipt_hash)
        computed_receipt_hash = rcpt.compute_receipt_hash()
        embedded = receipt.get("receipt_hash", "")
        if embedded and embedded != computed_receipt_hash:
            return False, f"Receipt {i}: receipt_hash mismatch"

        # Verify hash commitments when full invocations are provided
        inv = invocations.get(str(receipt.get("receipt_id", "")))
        if inv:
            def canon(obj):
                # Receipts commit tool I/O using Canonical JSON v1 (legacy/permissive).
                return canonical_json_dumps(obj, version="v1")

            if "params" in inv:
                # Hash-commit is over a params envelope to prevent tool/op mix-and-match.
                params_env = {"tool_name": rcpt.tool_name, "operation": rcpt.operation, "params": inv["params"]}
                if sha256_hex(canon(params_env).encode("utf-8")) != rcpt.params_hash:
                    return False, f"Receipt {i}: params_hash mismatch"
            if "result" in inv:
                if sha256_hex(canon(inv["result"]).encode("utf-8")) != receipt.get("result_hash"):
                    return False, f"Receipt {i}: result_hash mismatch"
            if "response_envelope" in inv:
                if sha256_hex(canon(inv["response_envelope"]).encode("utf-8")) != receipt.get("response_hash", ""):
                    return False, f"Receipt {i}: response_hash mismatch"

        prev_hash = computed_receipt_hash

    return True, f"All {len(receipts)} receipt(s) verified"


def main(pack_dir: Path, *, allow_no_crypto: bool = False):
    """Main verification routine."""
    global ALLOW_NO_CRYPTO
    ALLOW_NO_CRYPTO = bool(allow_no_crypto)

    print(f"\nLAP Audit Pack Verification")
    print(f"Directory: {pack_dir}")
    print("=" * 50)

    if not CRYPTO_AVAILABLE and not ALLOW_NO_CRYPTO:
        print("ERROR: cryptography library is not installed.")
        if CRYPTO_IMPORT_ERROR:
            print(f"  Import error: {CRYPTO_IMPORT_ERROR}")
        print("Install with: pip install cryptography")
        print("Or re-run with: python verify.py <dir> --allow-no-crypto  (hash-only; signatures skipped)")
        return False

    if not CRYPTO_AVAILABLE and ALLOW_NO_CRYPTO:
        print("WARNING: cryptography not installed; proceeding in HASH-ONLY mode (signatures skipped).")
        print("         Install with: pip install cryptography")
        print()

    # Load manifest
    manifest_path = pack_dir / "manifest.json"
    if not manifest_path.exists():
        print("ERROR: manifest.json not found")
        return False

    manifest = load_json_file(manifest_path)
    canon_ver = str(manifest.get("canonical_json_version", "v1") or "v1")
    receipt_profile = str(manifest.get("receipt_profile", "v1") or "v1").lower().strip()

    print(f"Action ID: {manifest['action_id']}")
    print(f"Evidence Hash: {manifest['evidence_hash'][:16]}...")
    print(f"Decision Hash: {manifest['decision_hash'][:16]}...")
    print(f"Canonical JSON: {canon_ver}")
    print()

    # Load trusted keys
    keys_path = pack_dir / "trusted_keys.json"
    trusted_keys = load_json_file(keys_path) if keys_path.exists() else {}
    print(f"Trusted keys: {list(trusted_keys.keys())}")
    print()

    all_passed = True

    # Verify evidence
    print("1. Verifying evidence hash...")
    ok, msg = verify_evidence(pack_dir, manifest["evidence_hash"], canon_ver)
    print(f"   {'✓' if ok else '✗'} {msg}")
    all_passed = all_passed and ok

    # Verify decision
    print("2. Verifying decision hash...")
    ok, msg = verify_decision(pack_dir, manifest["decision_hash"], manifest["evidence_hash"], manifest["action_id"])
    print(f"   {'✓' if ok else '✗'} {msg}")
    all_passed = all_passed and ok

    # Verify external approval
    print("3. Verifying external approval...")
    ok, msg = verify_approval(pack_dir, trusted_keys)
    print(f"   {'✓' if ok else '✗'} {msg}")
    all_passed = all_passed and ok

    # Verify token
    print("4. Verifying capability token...")
    ok, msg = verify_token(pack_dir, trusted_keys)
    print(f"   {'✓' if ok else '✗'} {msg}")
    all_passed = all_passed and ok

    # Get token jti for receipt verification
    token_path = pack_dir / "token.json"
    token_jti = None
    if token_path.exists():
        token = load_json_file(token_path)
        token_jti = token.get("jti")

    # Verify receipts
    print("5. Verifying receipts...")
    ok, msg = verify_receipts(pack_dir, trusted_keys, token_jti, receipt_profile)
    print(f"   {'✓' if ok else '✗'} {msg}")
    all_passed = all_passed and ok

    print()
    print("=" * 50)
    if all_passed:
        print("VERIFICATION PASSED ✓")
        if not CRYPTO_AVAILABLE and ALLOW_NO_CRYPTO:
            print("NOTE: Hashes verified, but signatures were NOT checked.")
        else:
            print("This audit pack is cryptographically valid.")
    else:
        print("VERIFICATION FAILED ✗")
        print("This audit pack has integrity issues.")

    return all_passed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify a LAP audit pack (offline).")
    parser.add_argument("pack_dir", nargs="?", default=".", help="Path to extracted audit pack directory (default: .)")
    parser.add_argument(
        "--allow-no-crypto",
        action="store_true",
        help="Allow running without cryptography (hash-only; signatures skipped).",
    )
    args = parser.parse_args()

    pack_dir = Path(args.pack_dir)
    success = main(pack_dir, allow_no_crypto=args.allow_no_crypto)
    sys.exit(0 if success else 1)'''


VERIFY_README = '''# LAP Audit Pack Verification

This directory contains a cryptographically verifiable audit pack for a LAP-governed action.

## Quick Verification

```bash
python verify.py
```

Or specify a directory:

```bash
python verify.py /path/to/audit_pack
```

## Contents

| File | Description |
|------|-------------|
| `manifest.json` | Pack metadata with action_id, evidence_hash, decision_hash |
| `evidence.json` | Original evidence submitted for evaluation |
| `decision.json` | LAP decision record |
| `external_approval.json` | External reviewer approval (if T3) |
| `token.json` | Capability token issued (if approved) |
| `receipts.json` | Signed receipts for tool invocations |
| `invocations.json` | Optional full params/result/response objects for hash commitment checks |
| `trusted_keys.json` | Public keys for signature verification |
| `verify.py` | Verification script |
| `VERIFY.md` | This file |

## What Gets Verified

1. **Evidence Hash**: The evidence content matches its claimed hash
2. **Decision Hash**: The decision binds correctly to action_id + evidence_hash + outcome
3. **External Approval**: Ed25519 signature from trusted reviewer key
4. **Capability Token**: Ed25519 signature from gateway key
5. **Receipts**: 
   - Ed25519 signatures valid
   - Chain integrity (each receipt links to previous)
   - Token binding (receipts tied to correct token)
   - Hash commitments (params/result/response) if `invocations.json` provided

## Security Properties

- **Unforgeable**: Ed25519 signatures cannot be forged without private keys
- **Tamper-evident**: Any modification breaks hash/signature verification
- **Offline verifiable**: No database or network access required
- **Evidence-bound**: Approvals tied to specific evidence content, not just action_id

## Requirements

For full signature verification:

```bash
pip install cryptography
```

By default, verification FAILS CLOSED if `cryptography` is not installed.

If you explicitly want *hash-only* verification (signatures skipped), run the bundled `verify.py` with `--allow-no-crypto`.

## Trust Model

The `trusted_keys.json` file contains public keys that are trusted for verification.
You should verify these keys through an out-of-band channel (e.g., published on
your organization's security page).
'''


class AuditPackBuilder:
    """
    Builds audit packs for offline verification.
    """
    
    def __init__(self, gateway_id: str = "unknown", protocol_version: str = "2.0.0", canonical_json_version: str = "v2"):
        self.gateway_id = gateway_id
        self.protocol_version = protocol_version
        self.canonical_json_version = canonical_json_version
    
    def build_pack(
        self,
        action_id: str,
        evidence: Dict[str, Any],
        decision: Dict[str, Any],
        external_approval: Optional[Dict[str, Any]] = None,
        token: Optional[Dict[str, Any]] = None,
        receipts: Optional[List[Dict[str, Any]]] = None,
        invocations: Optional[List[Dict[str, Any]]] = None,
        trusted_keys: Optional[Dict[str, str]] = None,
        anchor: Optional[Dict[str, Any]] = None,
    ) -> AuditPackContents:
        """Build audit pack contents."""
        # Determine hashes (authoritative if provided)
        evidence_canonical = canonical_json_dumps(evidence, version=self.canonical_json_version)
        computed_evidence_hash = _sha256_hex(evidence_canonical.encode("utf-8"))

        computed_decision_hash = _sha256_hex(_safe_hash_encode([
            action_id,
            computed_evidence_hash,
            decision.get("outcome", ""),
            decision.get("tier", ""),
            decision.get("reason", ""),
        ]))

        token_evidence_hash = None
        token_decision_hash = None
        if token and isinstance(token, dict):
            payload_obj = token.get("payload") or {}
            token_evidence_hash = payload_obj.get("evidence_hash") or None
            token_decision_hash = payload_obj.get("decision_hash") or None

        receipt_evidence_hash = None
        receipt_decision_hash = None
        if receipts:
            eh_set = {r.get("evidence_hash") for r in receipts if isinstance(r, dict) and r.get("evidence_hash")}
            dh_set = {r.get("decision_hash") for r in receipts if isinstance(r, dict) and r.get("decision_hash")}
            if len(eh_set) == 1:
                receipt_evidence_hash = next(iter(eh_set))
            if len(dh_set) == 1:
                receipt_decision_hash = next(iter(dh_set))

        # Cross-artifact consistency checks (token vs receipts)
        if token_evidence_hash and receipt_evidence_hash and token_evidence_hash != receipt_evidence_hash:
            raise ValueError(f"Evidence hash mismatch between token and receipts: token={token_evidence_hash}, receipts={receipt_evidence_hash}")
        if token_decision_hash and receipt_decision_hash and token_decision_hash != receipt_decision_hash:
            raise ValueError(f"Decision hash mismatch between token and receipts: token={token_decision_hash}, receipts={receipt_decision_hash}")

        # Choose authoritative hashes if present; otherwise use computed
        evidence_hash = token_evidence_hash or receipt_evidence_hash or computed_evidence_hash
        decision_hash = token_decision_hash or receipt_decision_hash or computed_decision_hash

        # Validate that supplied evidence/decision match the governed hashes
        if (token_evidence_hash or receipt_evidence_hash) and evidence_hash != computed_evidence_hash:
            raise ValueError(
                f"Evidence dict does not match governed evidence_hash: governed={evidence_hash}, computed={computed_evidence_hash}. "
                "Ensure you pass the exact evidence used at decision time."
            )
        if (token_decision_hash or receipt_decision_hash) and decision_hash != computed_decision_hash:
            raise ValueError(
                f"Decision fields do not match governed decision_hash: governed={decision_hash}, computed={computed_decision_hash}. "
                "Ensure decision outcome/tier/reason and evidence match the governed decision."
            )
        
        return AuditPackContents(
            action_id=action_id,
            evidence_hash=evidence_hash,
            decision_hash=decision_hash,
            evidence_json=json.dumps(evidence, indent=2, ensure_ascii=False),
            decision_json=json.dumps(decision, indent=2, default=str),
            external_approval_json=json.dumps(external_approval, indent=2) if external_approval else None,
            token_json=json.dumps(token, indent=2) if token else None,
            receipts_json=json.dumps(receipts or [], indent=2),
            invocations_json=json.dumps(invocations, indent=2, default=str) if invocations is not None else None,
            anchor_json=json.dumps(anchor, indent=2) if anchor else None,
            trusted_keys_json=json.dumps(trusted_keys or {}, indent=2),
            created_at_utc=_now_utc().isoformat(),
            gateway_id=self.gateway_id,
            protocol_version=self.protocol_version,
            canonical_json_version=self.canonical_json_version,
        )
    
    def write_pack(
        self,
        contents: AuditPackContents,
        output_path: str,
        *,
        export_attestation_files: bool = False,
        dsse_key_store: Optional[Any] = None,
        dsse_key_id: str = "",
        export_anchors_jsonl: bool = False,
        anchors_include_receipts: bool = True,
        anchors_include_dsse: bool = True,
    ) -> str:
        """
        Write audit pack to a ZIP file.
        
        Returns path to created ZIP file.
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as tmpdir:
            pack_dir = Path(tmpdir) / "audit_pack"
            pack_dir.mkdir()
            
            # Write manifest
            manifest = {
                "action_id": contents.action_id,
                "evidence_hash": contents.evidence_hash,
                "decision_hash": contents.decision_hash,
                "created_at_utc": contents.created_at_utc,
                "gateway_id": contents.gateway_id,
                "protocol_version": contents.protocol_version,
                "canonical_json_version": contents.canonical_json_version,
                "receipt_profile": contents.receipt_profile,
            }
            (pack_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
            
            # Write evidence
            (pack_dir / "evidence.json").write_text(contents.evidence_json)
            
            # Write decision
            (pack_dir / "decision.json").write_text(contents.decision_json)
            
            # Write external approval (optional)
            if contents.external_approval_json:
                (pack_dir / "external_approval.json").write_text(contents.external_approval_json)
            
            # Write token (optional)
            if contents.token_json:
                (pack_dir / "token.json").write_text(contents.token_json)
            
            # Write receipts
            (pack_dir / "receipts.json").write_text(contents.receipts_json)

            # Write attestation statements (one per *tool invocation* receipt)
            # Additive: older verifiers ignore this file.
            receipts_list = json.loads(contents.receipts_json) if contents.receipts_json else []
            lines: list[str] = []
            stmts: list[dict] = []
            for r in receipts_list:
                try:
                    stmt = receipt_to_attestation_statement(r, manifest)
                except Exception:
                    # Some receipt variants (e.g., denial receipts) do not map to this
                    # predicate type. Skip them rather than breaking pack export.
                    continue
                stmts.append(stmt)
                lines.append(json.dumps(stmt, separators=(",", ":"), ensure_ascii=False))
            (pack_dir / "attestations.jsonl").write_text("\n".join(lines) + ("\n" if lines else ""))

            # Optionally export a single statement + DSSE envelope (PR-004)
            # These are convenience artifacts for ecosystem interop.
            if export_attestation_files and len(stmts) == 1:
                stmt0 = stmts[0]
                (pack_dir / "attestation.statement.json").write_text(
                    json.dumps(stmt0, indent=2, ensure_ascii=False), encoding="utf-8"
                )
                if dsse_key_store is not None and str(dsse_key_id or "").strip():
                    payload_bytes = json.dumps(stmt0, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                    env = make_envelope(payload_type=str(stmt0.get("_type", "")), payload_bytes=payload_bytes)
                    env = sign_envelope(env, dsse_key_store, str(dsse_key_id))
                    (pack_dir / "attestation.dsse.json").write_text(
                        json.dumps(env, indent=2, ensure_ascii=False), encoding="utf-8"
                    )

            # Optionally emit transparency anchors (PR-006)
            # One anchor entry per receipt and/or for the DSSE envelope (if present).
            if export_anchors_jsonl:
                anchors_path = pack_dir / "anchors.jsonl"
                logger = FileTransparencyLogger(anchors_path)
                entries = compute_anchor_entries_for_audit_pack_dir(
                    pack_dir,
                    include_receipts=anchors_include_receipts,
                    include_dsse=anchors_include_dsse,
                )
                for e in entries:
                    logger.append(e)

            # Write full invocations (optional)
            # NOTE: we treat empty lists ("[]") as present for audit completeness.
            if contents.invocations_json is not None:
                (pack_dir / "invocations.json").write_text(contents.invocations_json)
            
            # Write anchor (optional)
            if contents.anchor_json:
                (pack_dir / "anchor.json").write_text(contents.anchor_json)
            
            # Write trusted keys
            (pack_dir / "trusted_keys.json").write_text(contents.trusted_keys_json)
            
            # Write verification script
            (pack_dir / "verify.py").write_text(VERIFY_SCRIPT)
            
            # Write verification instructions
            (pack_dir / "VERIFY.md").write_text(VERIFY_README)
            
            # Create ZIP
            zip_path = Path(output_path)
            if zip_path.suffix != ".zip":
                zip_path = zip_path.with_suffix(".zip")
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file in pack_dir.iterdir():
                    zf.write(file, file.name)
            
            return str(zip_path)
    
    def extract_and_verify(self, zip_path: str) -> Tuple[bool, List[str]]:
        """
        Extract and verify an audit pack.
        
        Returns (success, messages).
        """
        messages = []
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Extract
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(tmpdir)
            
            pack_dir = Path(tmpdir)
            
            # Load manifest
            manifest_path = pack_dir / "manifest.json"
            if not manifest_path.exists():
                return False, ["manifest.json not found"]
            
            with open(manifest_path) as f:
                manifest = json.load(f)
            
            # Verify evidence hash
            evidence_path = pack_dir / "evidence.json"
            if evidence_path.exists():
                with open(evidence_path) as f:
                    evidence = json.load(f)
                canon_ver = str(manifest.get("canonical_json_version", "v1") or "v1")
                canonical = canonical_json_dumps(evidence, version=canon_ver)
                actual_hash = _sha256_hex(canonical.encode("utf-8"))
                
                if actual_hash == manifest["evidence_hash"]:
                    messages.append(f"✓ Evidence hash verified: {actual_hash[:16]}...")
                else:
                    messages.append(f"✗ Evidence hash MISMATCH")
                    return False, messages
            else:
                messages.append("✗ evidence.json not found")
                return False, messages
            
            # Verify decision hash
            decision_path = pack_dir / "decision.json"
            if decision_path.exists():
                with open(decision_path) as f:
                    decision = json.load(f)
                
                components = [
                    manifest["action_id"],
                    manifest["evidence_hash"],
                    decision.get("outcome", ""),
                    decision.get("tier", ""),
                    decision.get("reason", ""),
                ]
                actual_hash = _sha256_hex(_safe_hash_encode(components))
                
                if actual_hash == manifest["decision_hash"]:
                    messages.append(f"✓ Decision hash verified: {actual_hash[:16]}...")
                else:
                    messages.append(f"✗ Decision hash MISMATCH")
                    return False, messages
            else:
                messages.append("✗ decision.json not found")
                return False, messages
            
            messages.append("✓ Audit pack verified successfully")
            return True, messages


def create_audit_pack(
    action_id: str,
    evidence: Dict[str, Any],
    decision: Dict[str, Any],
    output_path: str,
    external_approval: Optional[Dict[str, Any]] = None,
    token: Optional[Dict[str, Any]] = None,
    receipts: Optional[List[Dict[str, Any]]] = None,
    invocations: Optional[List[Dict[str, Any]]] = None,
    trusted_keys: Optional[Dict[str, str]] = None,
    gateway_id: str = "unknown",
) -> str:
    """
    Create an audit pack ZIP file.
    
    Convenience function for one-off pack creation.
    
    Returns path to created ZIP file.
    """
    builder = AuditPackBuilder(gateway_id=gateway_id)
    contents = builder.build_pack(
        action_id=action_id,
        evidence=evidence,
        decision=decision,
        external_approval=external_approval,
        token=token,
        receipts=receipts,
        invocations=invocations,
        trusted_keys=trusted_keys,
    )
    return builder.write_pack(contents, output_path)
