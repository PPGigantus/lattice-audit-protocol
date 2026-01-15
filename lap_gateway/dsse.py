"""lap_gateway.dsse: DSSE-inspired envelopes for signed attestations.

This is intentionally *DSSE-style* rather than a full DSSE implementation.

Envelope format:

    envelope = {
        "payloadType": "...",
        "payload": "<base64(payload_bytes)>",
        "signatures": [
            {"keyid": "...", "sig": "<base64(sig_bytes)>"}
        ]
    }

Signing model:
- We sign a canonical, length-prefixed encoding of:
    (payloadType, payload_base64)
- This binds the signature to both payload type and bytes without relying
  on JSON serialization of the envelope.

Compatibility:
- Uses existing Ed25519 utilities in lap_gateway.crypto.
- Additive: does not change receipt signing.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, Optional

from .crypto import Ed25519KeyPair, TrustedKeyStore, _safe_hash_encode
from .signing import Signer, coerce_signer


def make_envelope(payload_type: str, payload_bytes: bytes) -> Dict[str, Any]:
    """Create an unsigned envelope."""
    if not isinstance(payload_type, str) or not payload_type.strip():
        raise ValueError("payload_type must be a non-empty string")
    if not isinstance(payload_bytes, (bytes, bytearray)):
        raise TypeError("payload_bytes must be bytes")
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(bytes(payload_bytes)).decode("ascii"),
        "signatures": [],
    }


def _signing_payload(envelope: Dict[str, Any]) -> bytes:
    """Compute the canonical signing payload for an envelope."""
    if not isinstance(envelope, dict):
        raise TypeError("envelope must be a dict")
    payload_type = envelope.get("payloadType")
    payload_b64 = envelope.get("payload")
    if not isinstance(payload_type, str) or not payload_type.strip():
        raise ValueError("envelope.payloadType must be a non-empty string")
    if not isinstance(payload_b64, str) or not payload_b64.strip():
        raise ValueError("envelope.payload must be a non-empty base64 string")

    # Bind signature to the *exact* payload bytes (via canonical base64 string)
    # and the declared payloadType.
    return _safe_hash_encode([payload_type, payload_b64])


def _resolve_signing_key(key_store: Any, key_id: str) -> Signer:
    """Resolve a signer from a flexible key_store input.

    Accepts:
      - a Signer instance
      - a dict mapping key_id -> Signer
      - an object with get_signer()/get_signing_key()/get_key() returning a Signer
    """
    if not key_id or not str(key_id).strip():
        raise ValueError("key_id must be non-empty")
    kid = str(key_id).strip()

    # Direct signer
    if isinstance(key_store, Signer) or hasattr(key_store, "sign"):
        try:
            signer = coerce_signer(key_store)
            if signer.key_id != kid:
                raise KeyError(f"Signing key id mismatch: expected {kid!r}, got {signer.key_id!r}")
            return signer
        except TypeError:
            pass

    # Mapping style
    if isinstance(key_store, dict):
        key = key_store.get(kid)
        if key is None:
            raise KeyError(f"Signing key not found: {kid}")
        return coerce_signer(key)

    # Objects with get_signer / get_signing_key / get_key
    for attr in ("get_signer", "get_signing_key", "get_key"):
        getter = getattr(key_store, attr, None)
        if callable(getter):
            key = getter(kid)
            if key is None:
                raise KeyError(f"Signing key not found: {kid}")
            return coerce_signer(key)

    raise TypeError("Unsupported key_store type for signing")



def sign_envelope(envelope: Dict[str, Any], key_store: Any, key_id: str) -> Dict[str, Any]:
    """Sign an envelope and append/replace the signature entry for key_id."""
    sig_payload = _signing_payload(envelope)
    signer = _resolve_signing_key(key_store, key_id)
    sig = signer.sign(sig_payload)

    sig_entry = {"keyid": signer.key_id, "sig": base64.b64encode(sig).decode("ascii")}
    out = {
        "payloadType": envelope.get("payloadType"),
        "payload": envelope.get("payload"),
        "signatures": list(envelope.get("signatures") or []),
    }

    # Replace existing entry for this keyid if present; otherwise append.
    replaced = False
    new_sigs = []
    for entry in out["signatures"]:
        if isinstance(entry, dict) and str(entry.get("keyid", "")) == signer.key_id:
            new_sigs.append(sig_entry)
            replaced = True
        else:
            new_sigs.append(entry)
    if not replaced:
        new_sigs.append(sig_entry)
    out["signatures"] = new_sigs
    return out


def _verify_with_trusted(
    trusted_keys: Any,
    key_id: str,
    message: bytes,
    signature: bytes,
    *,
    signed_at_utc: Optional[str] = None,
) -> bool:
    """Verify signature against a flexible trusted_keys input.

    Accepts either a TrustedKeyStore or a dict in either legacy or registry format.
    """
    kid = str(key_id)
    if isinstance(trusted_keys, TrustedKeyStore):
        return trusted_keys.verify_signature(kid, message, signature, signed_at_utc=signed_at_utc)

    if isinstance(trusted_keys, dict):
        try:
            store = TrustedKeyStore.from_config(trusted_keys)
        except Exception:
            return False
        return store.verify_signature(kid, message, signature, signed_at_utc=signed_at_utc)

    return False

def verify_envelope(envelope: Dict[str, Any], trusted_keys: Any) -> bool:
    """Verify that at least one signature on the envelope is valid."""
    try:
        msg = _signing_payload(envelope)
    except Exception:
        return False

    signed_at_utc: Optional[str] = None
    try:
        payload_b = base64.b64decode(str(envelope.get("payload", "")))
        obj = json.loads(payload_b.decode("utf-8"))
        if isinstance(obj, dict):
            meta = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else None
            if isinstance(meta, dict) and isinstance(meta.get("created_at_utc"), str):
                signed_at_utc = str(meta.get("created_at_utc"))
            elif isinstance(obj.get("created_at_utc"), str):
                signed_at_utc = str(obj.get("created_at_utc"))
    except Exception:
        signed_at_utc = None

    sigs = envelope.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        return False

    for entry in sigs:
        if not isinstance(entry, dict):
            continue
        keyid = entry.get("keyid")
        sig_b64 = entry.get("sig")
        if not isinstance(keyid, str) or not keyid.strip():
            continue
        if not isinstance(sig_b64, str) or not sig_b64.strip():
            continue
        try:
            sig = base64.b64decode(sig_b64)
        except Exception:
            continue
        if _verify_with_trusted(trusted_keys, keyid, msg, sig, signed_at_utc=signed_at_utc):
            return True

    return False
