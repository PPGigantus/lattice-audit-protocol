"""
LAP Gateway Cryptography Module (v2.0)

Ed25519 asymmetric signatures for external approvals and capability tokens.
This replaces HMAC shared-secret signatures, providing true separation of duties:
- Protocol holds only PUBLIC keys (can verify, cannot sign)
- External reviewers hold PRIVATE keys (can sign approvals)

Even if an agent compromises the entire protocol, it cannot forge approvals.
"""

import hashlib
import json
import unicodedata
from .errors import (
    LAPError,
    lap_error,
    LAP_E_CANON_NON_JSON,
    LAP_E_CANON_DEPTH,
    LAP_E_CANON_NONFINITE,
    LAP_E_CANON_KEY_TYPE,
    LAP_E_CANON_KEY_COLLISION,
    LAP_E_CANON_INT_TOO_LARGE,
)
import math
import base64
import secrets
import re
import os
import subprocess
import shlex
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Tuple, List, Set
from datetime import datetime, timezone

# Try to import cryptography library for Ed25519
# Falls back to stub implementation for development
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    Ed25519PrivateKey = None
    Ed25519PublicKey = None


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _parse_iso_utc(ts: Optional[str]) -> Optional[datetime]:
    """Parse an ISO timestamp into a timezone-aware UTC datetime.

    Returns None if parsing fails or input is empty.
    """
    if not ts:
        return None
    try:
        s = str(ts).strip()
        if not s:
            return None
        # Accept RFC 3339 'Z' suffix.
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_hash_encode(components: List[str]) -> bytes:
    """
    Length-prefixed encoding for hash inputs.
    Prevents delimiter collision attacks.
    """
    result = b""
    for component in components:
        encoded = component.encode("utf-8")
        length_bytes = len(encoded).to_bytes(8, byteorder="big")
        result += length_bytes + encoded
    return result


def canonical_json_dumps_v1(obj: Any) -> str:
    """Canonical JSON v1 (legacy) for cross-language stable hashing/signing.

    v1 is intentionally permissive and stringifies non-JSON-serializable
    objects via ``default=str``.

    - sort_keys: deterministic key order
    - separators: no whitespace ambiguity
    - ensure_ascii=False: preserve unicode deterministically (UTF-8)
    - default=str: avoid crashes on datetimes/Decimals while keeping determinism
    """

    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)



# Canonical JSON v2: adversarial hardening
# - Enforce max depth to avoid pathological recursion/DoS inputs
# - Enforce bounded integers to preserve cross-language determinism
#   (many JSON decoders coerce numbers to float64 and lose precision)
# - Normalize unicode to NFC to prevent visually-identical but byte-distinct strings
_CANON_JSON_V2_MAX_DEPTH = 64
_CANON_JSON_V2_MAX_INT_DIGITS = 128
_CANON_JSON_V2_UNICODE_NORM = "NFC"


def _canon_json_v2_path_key(k: str) -> str:
    # JSONPath-ish: $['key'] with minimal escaping for readability
    ks = k.replace("\\", "\\\\").replace("'", "\\'")
    return f"['{ks}']"


def _canonicalize_json_v2(
    obj: Any,
    *,
    max_depth: int = _CANON_JSON_V2_MAX_DEPTH,
    max_int_digits: int = _CANON_JSON_V2_MAX_INT_DIGITS,
    unicode_norm: str = _CANON_JSON_V2_UNICODE_NORM,
    _path: str = "$",
    _depth: int = 0,
) -> Any:
    if max_depth < 1 or max_depth > 512:
        raise lap_error(LAP_E_CANON_NON_JSON, "max_depth must be in [1,512]", http_status=400)
    if _depth > max_depth:
        raise lap_error(LAP_E_CANON_DEPTH, "max nesting depth exceeded", path=_path, max_depth=max_depth, http_status=400)

    # Scalars
    if obj is None or isinstance(obj, bool):
        return obj
    if isinstance(obj, str):
        return unicodedata.normalize(unicode_norm, obj) if unicode_norm else obj
    if isinstance(obj, int):
        # bool is subclass of int; handled above
        # Limit digits to avoid pathological huge bignums used for DoS.
        digits = len(str(abs(obj)))
        if digits > int(max_int_digits):
            raise lap_error(LAP_E_CANON_INT_TOO_LARGE, "integer has too many digits", path=_path, digits=digits, max_int_digits=int(max_int_digits), http_status=400)
        return obj
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise lap_error(LAP_E_CANON_NONFINITE, "non-finite float", path=_path, http_status=400)
        return obj

    # Containers
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if not isinstance(k, str):
                raise lap_error(LAP_E_CANON_KEY_TYPE, "dict key must be str", path=_path, got=type(k).__name__, http_status=400)
            nk = unicodedata.normalize(unicode_norm, k) if unicode_norm else k
            if nk in out:
                # Normalization can collapse distinct keys into the same NFC form.
                raise lap_error(LAP_E_CANON_KEY_COLLISION, "duplicate dict key after unicode normalization", path=_path, http_status=400)
            child_path = _path + _canon_json_v2_path_key(nk)
            out[nk] = _canonicalize_json_v2(
                v,
                max_depth=max_depth,
                max_int_digits=max_int_digits,
                unicode_norm=unicode_norm,
                _path=child_path,
                _depth=_depth + 1,
            )
        return out

    if isinstance(obj, (list, tuple)):
        return [
            _canonicalize_json_v2(
                v,
                max_depth=max_depth,
                max_int_digits=max_int_digits,
                unicode_norm=unicode_norm,
                _path=f"{_path}[{i}]",
                _depth=_depth + 1,
            )
            for i, v in enumerate(list(obj))
        ]

    raise lap_error(LAP_E_CANON_NON_JSON, "non-JSON-serializable type", path=_path, got=type(obj).__name__, http_status=400)


def canonical_json_dumps_v2(obj: Any) -> str:
    """Canonical JSON v2 (strict + hardened).

    v2 is the recommended standard going forward. It is strict JSON:
    it does NOT stringify unknown types. If an object contains a
    non-JSON-serializable value, a TypeError is raised.

    Additional hardening:
      - Enforces max nesting depth to prevent pathological inputs.
      - Limits integer digit length to prevent DoS while preserving large integers exactly.
      - Normalizes unicode strings (and dict keys) to NFC to avoid byte-level ambiguity.
    """

    try:
        normalized = _canonicalize_json_v2(obj)
        # NOTE: allow_nan=False enforces strict JSON. This matches Go's encoding/json,
        # which rejects NaN/Infinity. Without this, Python could hash/sign a value
        # that other verifiers cannot re-encode.
        return json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except LAPError:
        raise
    except (TypeError, ValueError) as e:
        raise TypeError(
            "canonical_json_dumps_v2: object contains non-JSON-serializable "
            f"types or non-canonical primitives. Original error: {e}"
        ) from e

def canonical_json_dumps(obj: Any, *, version: str = "v2") -> str:
    """Canonical JSON dispatch.

    Args:
        obj: object to encode.
        version: "v1" (legacy permissive) or "v2" (strict). Default is "v2".

    Note:
        Many parts of LAP still explicitly use v1 to preserve backwards
        compatibility of existing hashes/signatures. New artifacts should
        prefer v2.
    """

    v = (version or "v2").lower()
    if v in {"1", "v1", "legacy"}:
        return canonical_json_dumps_v1(obj)
    if v in {"2", "v2", "strict"}:
        return canonical_json_dumps_v2(obj)
    raise ValueError(f"Unknown canonical JSON version: {version!r} (expected 'v1' or 'v2')")


class _CallableStr(str):
    """A string that can also be called like a function.

    This is used to preserve backwards compatibility for older code that did
    `key.public_key_hex()` while allowing newer code to treat
    `key.public_key_hex` as data.
    """

    def __call__(self) -> "_CallableStr":
        return self


@dataclass
class Ed25519KeyPair:
    """
    Ed25519 key pair for signing and verification.
    
    SECURITY: Private keys should NEVER be stored in the protocol config.
    They should only exist on external signing devices (YubiKey, HSM, etc.)
    """
    key_id: str
    public_key_bytes: bytes
    private_key_bytes: Optional[bytes] = None  # Only for key generation/testing
    is_stub: bool = False  # Insecure shared-secret stub mode (dev only)
    
    @classmethod
    def generate(cls, key_id: str) -> "Ed25519KeyPair":
        """Generate a new Ed25519 key pair."""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required for Ed25519. Install with: pip install cryptography")
        
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return cls(
            key_id=key_id,
            public_key_bytes=public_bytes,
            private_key_bytes=private_bytes
        )
    
    @classmethod
    def from_public_key(cls, key_id: str, public_key_hex: str) -> "Ed25519KeyPair":
        """Create key pair with public key only (for verification)."""
        return cls(
            key_id=key_id,
            public_key_bytes=bytes.fromhex(public_key_hex),
            private_key_bytes=None,
            is_stub=(not CRYPTO_AVAILABLE and os.environ.get("LAP_ALLOW_INSECURE_STUB_CRYPTO") == "1"),
        )
    
    @classmethod
    def from_seed(cls, seed: bytes, key_id: str) -> "Ed25519KeyPair":
        """
        Create key pair from 32-byte seed.
        
        HARDENING (v2.0.2): Supports deterministic key generation from
        securely stored seed material.
        
        Args:
            seed: 32-byte seed (e.g., from secure storage or KDF)
            key_id: Identifier for the key
            
        Returns Ed25519KeyPair with both public and private keys.
        """
        if len(seed) != 32:
            raise ValueError(f"Seed must be 32 bytes, got {len(seed)}")
        
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required for from_seed")
        
        # Ed25519 derives the full private key from the seed
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
        public_key = private_key.public_key()
        
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return cls(
            key_id=key_id,
            public_key_bytes=public_bytes,
            private_key_bytes=private_bytes
        )
    
    @property
    def public_key_hex(self) -> str:
        """Public key as a hex string.

        This is exposed as a property because it is frequently treated as data
        (e.g., stored in config or audit bundles).
        """
        return _CallableStr(self.public_key_bytes.hex())

    def public_key_hex_str(self) -> str:
        """Backward-compatible accessor for the public key hex string."""
        return self.public_key_hex
    
    def can_sign(self) -> bool:
        """Check if this key pair can sign (has private key)."""
        return self.private_key_bytes is not None
    
    def sign(self, message: bytes) -> bytes:
        """Sign a message with the private key."""
        if not CRYPTO_AVAILABLE:
            # Development-only insecure stub mode (shared-secret HMAC).
            if os.environ.get("LAP_ALLOW_INSECURE_STUB_CRYPTO") == "1" and self.is_stub:
                import hmac
                if not self.can_sign():
                    raise ValueError(f"Key {self.key_id} has no private key - cannot sign")
                # Use a shared 32-byte secret. In stub mode we store the secret in
                # private_key_bytes and derive public_key_bytes as the first 32 bytes.
                key = (self.private_key_bytes or b"")[:32] or self.public_key_bytes
                return hmac.new(key, message, hashlib.sha256).digest()
            raise RuntimeError("cryptography library required")
        if not self.can_sign():
            raise ValueError(f"Key {self.key_id} has no private key - cannot sign")

        private_key = Ed25519PrivateKey.from_private_bytes(self.private_key_bytes)
        return private_key.sign(message)
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature with the public key."""
        if not CRYPTO_AVAILABLE:
            # Development-only insecure stub mode (shared-secret HMAC).
            if os.environ.get("LAP_ALLOW_INSECURE_STUB_CRYPTO") == "1" and self.is_stub:
                import hmac
                expected = hmac.new(self.public_key_bytes, message, hashlib.sha256).digest()
                return hmac.compare_digest(signature, expected)
            raise RuntimeError("cryptography library required")

        try:
            public_key = Ed25519PublicKey.from_public_bytes(self.public_key_bytes)
            public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False



def _run_external_signer_cmd(*, signing_cmd: str, message: bytes, timeout_seconds: float) -> bytes:
    """Run an external signer command for an Ed25519 signature.

    stdin: base64(message)
    stdout: base64(signature)  (must be 64 bytes after decoding)
    """
    if not signing_cmd or not str(signing_cmd).strip():
        raise ValueError("External signer requires signing_cmd")
    msg_b64 = base64.b64encode(bytes(message)).decode("ascii")
    try:
        proc = subprocess.run(
            shlex.split(str(signing_cmd)),
            input=(msg_b64 + "\n").encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=float(timeout_seconds),
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"External signer timed out after {timeout_seconds}s") from e
    except Exception as e:
        raise RuntimeError(f"External signer failed to execute: {e}") from e

    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", errors="ignore").strip()
        raise RuntimeError(f"External signer returned code {proc.returncode}: {err}")

    out = (proc.stdout or b"").decode("utf-8", errors="ignore").strip()
    try:
        sig = base64.b64decode(out.encode("ascii"), validate=True)
    except Exception as e:
        raise RuntimeError("External signer output was not valid base64(signature)") from e

    if len(sig) != 64:
        raise RuntimeError(f"External signer returned invalid Ed25519 signature length: {len(sig)} bytes")
    return sig

class ExternalEd25519Signer:
    """Deprecated: use lap_gateway.signing.ExternalCommandSigner instead.

    Kept for backwards compatibility. This wraps an external signing command to
    produce Ed25519 signatures while the gateway process never holds private key
    material.

    Command contract:
      - stdin: base64(message)
      - stdout: base64(signature)   (must decode to 64 bytes)
    """

    def __init__(self, *, key_id: str, public_key_bytes: bytes, signing_cmd: str, timeout_seconds: float = 2.0):
        self.key_id = str(key_id)
        self.public_key_bytes = bytes(public_key_bytes)
        self.signing_cmd = str(signing_cmd)
        self.timeout_seconds = float(timeout_seconds)

    @property
    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()

    def sign(self, message: bytes) -> bytes:
        # Delegate to the shared external command runner.
        return _run_external_signer_cmd(
            signing_cmd=self.signing_cmd,
            message=bytes(message),
            timeout_seconds=self.timeout_seconds,
        )

    def verify(self, message: bytes, signature: bytes) -> bool:
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required for Ed25519 verification")
        try:
            public_key = Ed25519PublicKey.from_public_bytes(self.public_key_bytes)
            public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False


@dataclass
class RevocationRecord:
    """A time-bounded revocation for a key_id.

    If revoked_at is set, the key is considered INVALID for signatures at or after
    that timestamp, but signatures strictly before revoked_at remain verifiable
    ("trust at event time") and should emit a warning.
    """
    key_id: str
    revoked_at: Optional[datetime] = None
    reason: str = ""


@dataclass
class TrustedKeyRecord:
    """Metadata + parsed key material for a single trusted public key."""
    key_id: str
    keypair: 'Ed25519KeyPair'
    status: str = "active"  # active|revoked|inactive
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revoked_reason: str = ""


@dataclass
class TrustedKeyStore:
    """Store of trusted Ed25519 public keys for signature verification.

    Supports key rotation and revocation:
      - Multiple active keys
      - Absolute revocations (always fail verification)
      - Time-bounded revocations (fail if signed_at_utc >= revoked_at; otherwise
        pass with a warning)
      - Optional not_before/not_after validity windows (checked against the
        artifact's signed_at_utc when available; otherwise current time).

    SECURITY: This store should ONLY contain public keys. Private keys must
    be kept offline on signing devices.
    """
    records: Dict[str, TrustedKeyRecord] = field(default_factory=dict)
    revoked_key_ids: Set[str] = field(default_factory=set)  # absolute revocations
    revocations: Dict[str, RevocationRecord] = field(default_factory=dict)  # time-bounded revocations
    legacy_verify: bool = False  # If True, ignore not_before/not_after windows.

    def add_public_key(
        self,
        key_id: str,
        public_key_hex: str,
        *,
        status: str = "active",
        not_before_utc: Optional[str] = None,
        not_after_utc: Optional[str] = None,
        revoked: bool = False,
        revoked_at_utc: Optional[str] = None,
        revoked_reason: str = "",
    ) -> None:
        """Add a trusted public key with optional metadata."""
        kp = Ed25519KeyPair.from_public_key(key_id, public_key_hex)
        nb = _parse_iso_utc(not_before_utc) if not_before_utc else None
        na = _parse_iso_utc(not_after_utc) if not_after_utc else None
        ra = _parse_iso_utc(revoked_at_utc) if revoked_at_utc else None
        st = str(status or "active").lower().strip() or "active"

        # Absolute revocation semantics (legacy)
        is_abs_revoked = bool(revoked) or (st == "revoked" and ra is None)

        rec = TrustedKeyRecord(
            key_id=key_id,
            keypair=kp,
            status=("revoked" if is_abs_revoked else st),
            not_before=nb,
            not_after=na,
            revoked_at=ra,
            revoked_reason=str(revoked_reason or ""),
        )
        self.records[key_id] = rec
        if is_abs_revoked:
            self.revoked_key_ids.add(key_id)
        if ra is not None:
            # Time-bounded revocation. Do NOT add to absolute revoked set.
            self.revocations[key_id] = RevocationRecord(key_id=key_id, revoked_at=ra, reason=str(revoked_reason or ""))

    def revoke_key(self, key_id: str, *, revoked_at_utc: Optional[str] = None, reason: str = "") -> None:
        """Revoke a key either absolutely (no timestamp) or effective at a time."""
        kid = str(key_id)
        ra = _parse_iso_utc(revoked_at_utc) if revoked_at_utc else None
        if ra is None:
            self.revoked_key_ids.add(kid)
        else:
            self.revocations[kid] = RevocationRecord(key_id=kid, revoked_at=ra, reason=str(reason or ""))
        rec = self.records.get(kid)
        if rec is not None:
            if ra is None:
                rec.status = "revoked"
            rec.revoked_at = ra or rec.revoked_at
            if reason:
                rec.revoked_reason = str(reason)

    def get_key(self, key_id: str) -> Optional['Ed25519KeyPair']:
        """Get a keypair by ID (public-only)."""
        rec = self.records.get(key_id)
        return rec.keypair if rec else None

    def _effective_verify_time(self, signed_at_utc: Optional[str]) -> datetime:
        dt = _parse_iso_utc(signed_at_utc) if signed_at_utc else None
        return dt if dt is not None else _now_utc()

    def _revocation_info(self, kid: str) -> Tuple[Optional[datetime], str, bool]:
        """Return (revoked_at, reason, absolute_revoked)."""
        if kid in self.revoked_key_ids:
            return None, "", True
        rec = self.records.get(kid)
        if rec is not None and str(rec.status).lower() == "revoked" and rec.revoked_at is None:
            return None, rec.revoked_reason or "", True
        rr = self.revocations.get(kid)
        if rr and rr.revoked_at is not None:
            return rr.revoked_at, rr.reason or "", False
        if rec is not None and rec.revoked_at is not None:
            return rec.revoked_at, rec.revoked_reason or "", False
        return None, "", False

    def verify_signature_detailed(
        self,
        key_id: str,
        message: bytes,
        signature: bytes,
        *,
        signed_at_utc: Optional[str] = None,
        legacy_verify: Optional[bool] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        """Verify a signature and return detailed lifecycle info.

        Returns (ok, info) where ok means the signature is accepted under the
        key lifecycle rules. `info` may include a warning when the key is revoked
        effective at a later date (trust-at-event-time).
        """
        kid = str(key_id)
        info: Dict[str, Any] = {"key_id": kid}

        rec = self.records.get(kid)
        if rec is None:
            info.update({"crypto_ok": False, "failure": "unknown_key"})
            return False, info

        t = self._effective_verify_time(signed_at_utc)
        info["verify_time_utc"] = t.isoformat()

        revoked_at, revoked_reason, abs_revoked = self._revocation_info(kid)
        if abs_revoked:
            info.update({"crypto_ok": False, "failure": "revoked"})
            return False, info

        lv = self.legacy_verify if legacy_verify is None else bool(legacy_verify)
        if not lv:
            if rec.not_before is not None and t < rec.not_before:
                info.update({"crypto_ok": False, "failure": "not_yet_valid"})
                return False, info
            if rec.not_after is not None and t > rec.not_after:
                info.update({"crypto_ok": False, "failure": "expired"})
                return False, info

        # Time-bounded revocation semantics.
        if revoked_at is not None:
            info["revoked_at_utc"] = revoked_at.isoformat()
            if revoked_reason:
                info["revoked_reason"] = revoked_reason
            if t >= revoked_at:
                info.update({"crypto_ok": False, "failure": "revoked_effective"})
                return False, info
            # Trust at event time: accept, but warn.
            info["warning"] = "key_revoked_effective_later"

        # Crypto verification last
        crypto_ok = rec.keypair.verify(message, signature)
        info["crypto_ok"] = bool(crypto_ok)
        if not crypto_ok:
            info["failure"] = "bad_signature"
            return False, info

        return True, info

    def verify_signature(
        self,
        key_id: str,
        message: bytes,
        signature: bytes,
        *,
        signed_at_utc: Optional[str] = None,
        legacy_verify: Optional[bool] = None,
    ) -> bool:
        """Verify a signature using a trusted key (boolean result).

        See verify_signature_detailed for lifecycle warnings and metadata.
        """
        ok, _info = self.verify_signature_detailed(
            key_id,
            message,
            signature,
            signed_at_utc=signed_at_utc,
            legacy_verify=legacy_verify,
        )
        return bool(ok)

    def list_key_ids(self) -> List[str]:
        """List all known key IDs (including revoked/inactive)."""
        return list(self.records.keys())

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> 'TrustedKeyStore':
        """Create store from either:

        Legacy format:
            {"key_id": "<public_key_hex>", ...}

        Registry format (minimal):
            {
              "key_id": {"public_key_hex": "...", "status": "active"|"revoked",
                         "not_before_utc": "...", "not_after_utc": "...",
                         "revoked_at_utc": "...", "revoked_reason": "..."},
              ...
            }

        Or wrapped registry:
            {"version": 1, "keys": { ... }, "revoked": ["kid"], "revocations": [...], "legacy_verify": false}
        """
        store = cls()
        if not isinstance(config, dict):
            return store

        raw = config
        # Wrapped form: {"keys": {...}, "revoked": [...], "revocations": [...]}
        if isinstance(config.get("keys"), dict):
            raw = config.get("keys")  # type: ignore[assignment]
            if isinstance(config.get("legacy_verify"), bool):
                store.legacy_verify = bool(config.get("legacy_verify"))
            revoked_list = config.get("revoked")
            if isinstance(revoked_list, list):
                for kid in revoked_list:
                    if isinstance(kid, str) and kid.strip():
                        store.revoked_key_ids.add(kid)

            rev_list = config.get("revocations")
            if isinstance(rev_list, list):
                for rr in rev_list:
                    if not isinstance(rr, dict):
                        continue
                    kid = rr.get("key_id") or rr.get("kid") or rr.get("keyId")
                    if not isinstance(kid, str) or not kid.strip():
                        continue
                    ra = rr.get("revoked_at_utc") or rr.get("revoked_at")
                    reason = rr.get("reason") or rr.get("revoked_reason") or ""
                    store.revoke_key(kid, revoked_at_utc=ra if isinstance(ra, str) else None, reason=str(reason or ""))

        # Detect legacy map: all values are strings (public_key_hex)
        is_legacy_map = True
        for v in raw.values():
            if not isinstance(v, str):
                is_legacy_map = False
                break
        if is_legacy_map:
            for kid, pub_hex in raw.items():
                if isinstance(kid, str) and isinstance(pub_hex, str):
                    store.add_public_key(kid, pub_hex)
            # Apply explicit absolute revocations if any
            for kid in list(store.revoked_key_ids):
                store.revoke_key(kid)
            return store

        # Registry map: key_id -> entry dict
        for kid, entry in raw.items():
            if not isinstance(kid, str) or not kid.strip():
                continue
            if not isinstance(entry, dict):
                continue
            pub_hex = entry.get("public_key_hex") or entry.get("public_key") or entry.get("public_key_hex".upper())
            if not isinstance(pub_hex, str):
                continue
            status = entry.get("status", "active")
            nb = entry.get("not_before_utc") or entry.get("not_before")
            na = entry.get("not_after_utc") or entry.get("not_after")
            revoked = bool(entry.get("revoked", False))
            ra = entry.get("revoked_at_utc") or entry.get("revoked_at")
            rr = entry.get("revoked_reason") or entry.get("reason") or ""
            store.add_public_key(
                kid,
                pub_hex,
                status=str(status),
                not_before_utc=nb if isinstance(nb, str) else None,
                not_after_utc=na if isinstance(na, str) else None,
                revoked=revoked,
                revoked_at_utc=ra if isinstance(ra, str) else None,
                revoked_reason=str(rr or ""),
            )

        # Apply any explicit absolute revocation list from wrapper or top-level
        revoked_top = config.get("revoked")
        if isinstance(revoked_top, list):
            for rk in revoked_top:
                if isinstance(rk, str) and rk.strip():
                    store.revoke_key(rk)

        # Apply top-level time-bounded revocations if present (non-wrapped configs)
        rev_list2 = config.get("revocations")
        if isinstance(rev_list2, list):
            for rr in rev_list2:
                if not isinstance(rr, dict):
                    continue
                kid = rr.get("key_id") or rr.get("kid") or rr.get("keyId")
                if not isinstance(kid, str) or not kid.strip():
                    continue
                ra = rr.get("revoked_at_utc") or rr.get("revoked_at")
                reason = rr.get("reason") or rr.get("revoked_reason") or ""
                store.revoke_key(kid, revoked_at_utc=ra if isinstance(ra, str) else None, reason=str(reason or ""))

        return store

@dataclass
class SignedMessage:
    """
    A signed message with Ed25519 signature.
    
    Used for external approvals, capability tokens, and receipts.
    """
    payload: bytes
    signature: bytes
    key_id: str
    signed_at_utc: str = ""
    
    def __post_init__(self):
        if not self.signed_at_utc:
            self.signed_at_utc = _now_utc().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload": base64.b64encode(self.payload).decode('ascii'),
            "signature": base64.b64encode(self.signature).decode('ascii'),
            "key_id": self.key_id,
            "signed_at_utc": self.signed_at_utc,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SignedMessage":
        return cls(
            payload=base64.b64decode(data["payload"]),
            signature=base64.b64decode(data["signature"]),
            key_id=data["key_id"],
            signed_at_utc=data.get("signed_at_utc", ""),
        )
    
    def verify(self, key_store: TrustedKeyStore) -> bool:
        """Verify signature using trusted key store."""
        return key_store.verify_signature(self.key_id, self.payload, self.signature, signed_at_utc=self.signed_at_utc)
    
    @classmethod
    def create(cls, payload: bytes, key_pair: Ed25519KeyPair) -> "SignedMessage":
        """Create a signed message using a key pair."""
        signature = key_pair.sign(payload)
        return cls(
            payload=payload,
            signature=signature,
            key_id=key_pair.key_id,
        )


# ---------------------------
# External Review with Ed25519
# ---------------------------

@dataclass
class Ed25519ExternalApproval:
    """
    External approval with Ed25519 signature.
    
    SECURITY PROPERTIES:
    - Bound to specific evidence_hash (no approval reuse)
    - Asymmetric signature (protocol cannot forge)
    - Includes reviewer identity and timestamp
    
    HARDENING (v2.0.1): Rejects empty action_id/evidence_hash to prevent
    "empty hash approval" bypass attacks.
    
    HARDENING (v2.0.2): Requires evidence_hash to be valid SHA256 hex (64 chars).
    """
    action_id: str
    evidence_hash: str
    reviewer_id: str
    reviewer_type: str
    decision: str  # "approve", "deny", "request_more_info"
    confidence: float
    reasoning: str
    conditions: List[str]
    reviewed_at_utc: str
    signature: bytes
    key_id: str
    
    # Regex for valid SHA256 hex
    _SHA256_HEX_PATTERN = re.compile(r'^[0-9a-f]{64}$', re.IGNORECASE)
    
    def __post_init__(self):
        """Validate required fields."""
        if not self.action_id or not self.action_id.strip():
            raise ValueError("APPROVAL_VALIDATION_FAILED: action_id cannot be empty")
        if not self.evidence_hash or not self.evidence_hash.strip():
            raise ValueError("APPROVAL_VALIDATION_FAILED: evidence_hash cannot be empty")
        
        # HARDENING (v2.0.2): Require valid SHA256 hex format
        if not self._SHA256_HEX_PATTERN.match(self.evidence_hash):
            raise ValueError(
                f"APPROVAL_VALIDATION_FAILED: evidence_hash must be 64 hex chars (SHA256), "
                f"got {len(self.evidence_hash)} chars"
            )
    
    def compute_signature_payload(self) -> bytes:
        """Compute the canonical payload for signing."""
        components = [
            self.action_id,
            self.evidence_hash,
            self.reviewer_id,
            self.reviewer_type,
            self.decision,
            f"{self.confidence:.8f}",
            self.reasoning,
            ",".join(sorted(self.conditions)),
            self.reviewed_at_utc,
        ]
        return _safe_hash_encode(components)
    
    def verify(self, key_store: TrustedKeyStore) -> bool:
        """
        Verify the approval signature.
        
        HARDENING (v2.0.2): Fails closed if evidence_hash not valid SHA256 hex.
        """
        # Fail closed on empty/invalid binding fields
        if not self.action_id or not self.evidence_hash:
            return False
        if not self._SHA256_HEX_PATTERN.match(self.evidence_hash):
            return False
        if not self.signature or not self.key_id:
            return False
        
        payload = self.compute_signature_payload()
        return key_store.verify_signature(self.key_id, payload, self.signature, signed_at_utc=self.reviewed_at_utc)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "evidence_hash": self.evidence_hash,
            "reviewer_id": self.reviewer_id,
            "reviewer_type": self.reviewer_type,
            "decision": self.decision,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "conditions": self.conditions,
            "reviewed_at_utc": self.reviewed_at_utc,
            "signature": base64.b64encode(self.signature).decode('ascii'),
            "key_id": self.key_id,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Ed25519ExternalApproval":
        """
        Deserialize from dict.
        
        HARDENING (v2.0.2): Validates evidence_hash is valid SHA256 hex.
        """
        action_id = data.get("action_id", "")
        evidence_hash = data.get("evidence_hash", "")
        
        # Validate before construction
        if not action_id or not action_id.strip():
            raise ValueError("APPROVAL_VALIDATION_FAILED: action_id cannot be empty")
        if not evidence_hash or not evidence_hash.strip():
            raise ValueError("APPROVAL_VALIDATION_FAILED: evidence_hash cannot be empty")
        if not cls._SHA256_HEX_PATTERN.match(evidence_hash):
            raise ValueError(
                f"APPROVAL_VALIDATION_FAILED: evidence_hash must be 64 hex chars (SHA256)"
            )
        
        return cls(
            action_id=action_id,
            evidence_hash=evidence_hash,
            reviewer_id=data["reviewer_id"],
            reviewer_type=data["reviewer_type"],
            decision=data["decision"],
            confidence=data["confidence"],
            reasoning=data["reasoning"],
            conditions=data.get("conditions", []),
            reviewed_at_utc=data["reviewed_at_utc"],
            signature=base64.b64decode(data["signature"]),
            key_id=data["key_id"],
        )
    
    @classmethod
    def create_signed(
        cls,
        action_id: str,
        evidence_hash: str,
        reviewer_id: str,
        reviewer_type: str,
        decision: str,
        confidence: float,
        reasoning: str,
        key_pair: Ed25519KeyPair,
        conditions: Optional[List[str]] = None,
    ) -> "Ed25519ExternalApproval":
        """
        Create a signed external approval.
        
        This should be called by the external review system (human panel, HSM, etc.),
        NOT by the protocol or agent.
        
        HARDENING (v2.0.2): Requires evidence_hash to be valid SHA256 hex (64 chars).
        """
        # Validate before signing (also validated in __post_init__, but fail fast here)
        if not action_id or not action_id.strip():
            raise ValueError("APPROVAL_VALIDATION_FAILED: action_id cannot be empty")
        if not evidence_hash or not evidence_hash.strip():
            raise ValueError("APPROVAL_VALIDATION_FAILED: evidence_hash cannot be empty")
        if not cls._SHA256_HEX_PATTERN.match(evidence_hash):
            raise ValueError(
                f"APPROVAL_VALIDATION_FAILED: evidence_hash must be 64 hex chars (SHA256), "
                f"got {len(evidence_hash)} chars"
            )
        
        reviewed_at = _now_utc().isoformat()
        
        approval = cls(
            action_id=action_id,
            evidence_hash=evidence_hash,
            reviewer_id=reviewer_id,
            reviewer_type=reviewer_type,
            decision=decision,
            confidence=confidence,
            reasoning=reasoning,
            conditions=conditions or [],
            reviewed_at_utc=reviewed_at,
            signature=b"",  # Will be set below
            key_id=key_pair.key_id,
        )
        
        payload = approval.compute_signature_payload()
        approval.signature = key_pair.sign(payload)
        
        return approval


# ---------------------------
# Stub implementation when cryptography not available
# ---------------------------

class StubEd25519KeyPair:
    """Stub for development without cryptography library."""
    
    def __init__(self, key_id: str):
        self.key_id = key_id
        self._secret = secrets.token_bytes(32)
    
    def sign(self, message: bytes) -> bytes:
        """Stub sign using HMAC (NOT SECURE - development only)."""
        import hmac
        return hmac.new(self._secret, message, hashlib.sha256).digest()
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Stub verify."""
        import hmac
        expected = hmac.new(self._secret, message, hashlib.sha256).digest()
        return hmac.compare_digest(signature, expected)



def create_key_pair(key_id: str) -> Ed25519KeyPair:
    """
    Create a key pair.

    SECURITY POSTURE:
    - In production / audit-grade mode, Ed25519 requires the `cryptography` package.
    - If cryptography is missing, we fail closed by default.
    - For local dev only, you may set LAP_ALLOW_INSECURE_STUB_CRYPTO=1 to enable an
      HMAC-based stub. Receipts/tokens produced in this mode are NOT audit-grade.
    """
    import os
    import warnings

    if CRYPTO_AVAILABLE:
        return Ed25519KeyPair.generate(key_id)

    if os.environ.get("LAP_ALLOW_INSECURE_STUB_CRYPTO") == "1":
        warnings.warn(
            "cryptography not available - using INSECURE HMAC stub crypto. "
            "Receipts/tokens are NOT audit-grade. Install cryptography for real Ed25519."
        )
        stub = StubEd25519KeyPair(key_id)
        # Return a minimally usable object with the Ed25519KeyPair shape so the rest of
        # the system can run in dev/test environments.
        return Ed25519KeyPair(
            key_id=key_id,
            public_key_bytes=stub._secret[:32],
            private_key_bytes=stub._secret,
            is_stub=True,
        )

    raise RuntimeError(
        "cryptography library required for Ed25519. Install with: pip install cryptography "
        "or set LAP_ALLOW_INSECURE_STUB_CRYPTO=1 for an insecure dev stub."
    )



# ---------------------------
# Key Management (v2.0.2)
# ---------------------------



def load_signing_key_from_env(
    env_var: str = "LAP_GATEWAY_SIGNING_KEY",
    key_id: str = "gateway",
) -> Optional[Ed25519KeyPair]:
    """Load the gateway signing key from environment variables.

    Priority:
    1) Hardware-backed / external signer hook (recommended for stronger boundary)
       - LAP_GATEWAY_SIGNING_CMD
       - LAP_GATEWAY_PUBLIC_KEY_HEX
       - optional LAP_GATEWAY_SIGNING_CMD_TIMEOUT_SECONDS

    2) Hex seed in env_var (baseline boundary)
       - env_var (default: LAP_GATEWAY_SIGNING_KEY)

    Returns None if not configured or invalid.
    """
    import os

    # Hardware-backed signer hook (TPM/HSM/secure enclave / remote signer)
    signing_cmd = os.environ.get("LAP_GATEWAY_SIGNING_CMD")
    public_key_hex = os.environ.get("LAP_GATEWAY_PUBLIC_KEY_HEX")
    if signing_cmd and public_key_hex:
        try:
            timeout = float(os.environ.get("LAP_GATEWAY_SIGNING_CMD_TIMEOUT_SECONDS", "2.0"))
            return ExternalEd25519Signer(
                key_id=key_id,
                public_key_bytes=bytes.fromhex(public_key_hex.strip()),
                signing_cmd=signing_cmd,
                timeout_seconds=timeout,
            )
        except Exception as e:
            import warnings
            warnings.warn(f"Failed to load external signer from env: {e}")
            return None

    # Baseline: hex seed in env var
    key_hex = os.environ.get(env_var)
    if not key_hex:
        return None

    try:
        # Expect 32-byte seed as 64 hex chars
        if len(key_hex) != 64:
            raise ValueError(f"Key must be 64 hex chars (32 bytes), got {len(key_hex)}")

        seed = bytes.fromhex(key_hex)
        if (not CRYPTO_AVAILABLE) and os.environ.get("LAP_ALLOW_INSECURE_STUB_CRYPTO") == "1":
            import warnings
            warnings.warn(
                "Loading signing key in INSECURE stub crypto mode. "
                "Receipts/tokens are NOT audit-grade."
            )
            return Ed25519KeyPair(
                key_id=key_id,
                public_key_bytes=seed[:32],
                private_key_bytes=seed,
                is_stub=True,
            )
        return Ed25519KeyPair.from_seed(seed, key_id)
    except Exception as e:
        import warnings
        warnings.warn(f"Failed to load signing key from {env_var}: {e}")
        return None


def load_signing_key_from_file(
    path: str,
    key_id: str = "gateway",
    require_strict_permissions: bool = True,
) -> Optional[Ed25519KeyPair]:
    """
    Load signing key from file with permission checks.
    
    HARDENING (v2.0.2): Enforces 0600 permissions on key file to prevent
    unauthorized access. Key file should contain hex-encoded seed (64 chars).
    
    Args:
        path: Path to key file
        key_id: Identifier for the key
        require_strict_permissions: If True, reject files with loose permissions
        
    Returns None if file doesn't exist or has invalid permissions/content.
    """
    import os
    import stat
    from pathlib import Path
    
    key_path = Path(path)
    
    if not key_path.exists():
        return None
    
    # Check permissions (Unix only)
    if require_strict_permissions and hasattr(os, 'stat'):
        try:
            file_stat = os.stat(path)
            mode = file_stat.st_mode
            
            # Require owner read/write only (0600)
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                import warnings
                warnings.warn(
                    f"Key file {path} has insecure permissions. "
                    f"Expected 0600, got {oct(mode & 0o777)}. "
                    f"Run: chmod 600 {path}"
                )
                return None
        except OSError:
            pass  # Skip permission check on platforms without stat
    
    try:
        with open(path, 'r') as f:
            key_hex = f.read().strip()
        
        if len(key_hex) != 64:
            raise ValueError(f"Key must be 64 hex chars (32 bytes), got {len(key_hex)}")
        
        seed = bytes.fromhex(key_hex)
        if (not CRYPTO_AVAILABLE) and os.environ.get("LAP_ALLOW_INSECURE_STUB_CRYPTO") == "1":
            import warnings
            warnings.warn(
                "Loading signing key in INSECURE stub crypto mode. "
                "Receipts/tokens are NOT audit-grade."
            )
            return Ed25519KeyPair(
                key_id=key_id,
                public_key_bytes=seed[:32],
                private_key_bytes=seed,
                is_stub=True,
            )
        return Ed25519KeyPair.from_seed(seed, key_id)
    except Exception as e:
        import warnings
        warnings.warn(f"Failed to load signing key from {path}: {e}")
        return None


def load_signing_key(
    env_var: str = "LAP_GATEWAY_SIGNING_KEY",
    file_path: Optional[str] = None,
    key_id: str = "gateway",
    generate_if_missing: bool = False,
) -> Optional[Ed25519KeyPair]:
    """
    Load signing key with fallback chain.
    
    HARDENING (v2.0.2): Provides secure key loading with multiple sources.
    
    Priority:
    1. Environment variable (for containers/CI)
    2. File path (for traditional deployments)
    3. Generate new key (if generate_if_missing=True)
    
    Args:
        env_var: Environment variable name containing hex seed
        file_path: Path to key file containing hex seed
        key_id: Identifier for the key
        generate_if_missing: If True, generate new key if none found
        
    Returns key pair or None.
    """
    # Try environment first
    key = load_signing_key_from_env(env_var, key_id)
    if key:
        return key
    
    # Try file
    if file_path:
        key = load_signing_key_from_file(file_path, key_id)
        if key:
            return key
    
    # Generate if allowed
    if generate_if_missing:
        import warnings
        warnings.warn(
            "No signing key found - generating ephemeral key. "
            "Set LAP_GATEWAY_SIGNING_KEY env var for production."
        )
        return create_key_pair(key_id)
    
    return None



# ---------------------------
# Gateway Key Rotation (v2.1 / v1.2.0)
# ---------------------------

def load_gateway_keyset(
    *,
    json_env: str = "LAP_GATEWAY_KEYSET_JSON",
    file_env: str = "LAP_GATEWAY_KEYSET_FILE",
) -> Optional[Dict[str, Any]]:
    """Load an optional gateway keyset (for key rotation).

    Expected structure (JSON):

        {
          "active_kid": "gw_2026_01",
          "keys": {
            "gw_2026_01": {"seed_hex": "<64 hex chars>"},
            "gw_2025_12": {"public_key_hex": "<64 hex chars>"}
          }
        }

    Accepted synonyms:
      - active_kid / active_key_id / active_key
      - keys / public_keys (map of kid -> public_key_hex)
      - per-key entry may be a string (treated as public_key_hex)

    If present, the *active* key must include either:
      - seed_hex (32-byte Ed25519 seed) OR
      - signing_cmd + public_key_hex (external signer)

    Returns the parsed dict, or None if not configured.
    """
    raw = (os.getenv(json_env, "") or "").strip()
    path = (os.getenv(file_env, "") or "").strip()

    if not raw and not path:
        return None

    try:
        if raw:
            data = json.loads(raw)
        else:
            with open(path, "r", encoding="utf-8") as f:
                data = json.loads(f.read())
        if not isinstance(data, dict):
            raise ValueError("Keyset must be a JSON object")
        return data
    except Exception as e:
        import warnings
        warnings.warn(f"Failed to load gateway keyset: {e}")
        return None


def load_gateway_signing_material(
    *,
    allow_ephemeral: bool = False,
) -> Tuple[Optional[Ed25519KeyPair], 'TrustedKeyStore', Dict[str, str]]:
    """Load gateway signing key + verifying keyset.

    Precedence:
      1) Keyset (LAP_GATEWAY_KEYSET_JSON / LAP_GATEWAY_KEYSET_FILE)
      2) Single key env/file (LAP_GATEWAY_SIGNING_KEY[_FILE]) + optional kid env
      3) Ephemeral generation (only if allow_ephemeral=True)

    Returns:
      (signing_key_or_None, verifying_store, public_key_map)

    Note: verifying_store contains ONLY gateway public keys (not reviewer keys).
    """
    def _validate_hex_keylen(label: str, hex_str: str, expected_len_bytes: int) -> str:
        hs = str(hex_str or "").strip().lower()
        if not hs:
            raise ValueError(f"{label} is empty")
        if not re.fullmatch(r"[0-9a-f]+", hs):
            raise ValueError(f"{label} must be hex")
        if len(hs) != expected_len_bytes * 2:
            raise ValueError(
                f"{label} must be {expected_len_bytes} bytes ({expected_len_bytes*2} hex chars)"
            )
        return hs

    public_keys: Dict[str, str] = {}
    signing_key: Optional[Ed25519KeyPair] = None

    keyset = load_gateway_keyset()
    if keyset:
        active_kid = (
            str(keyset.get("active_kid") or keyset.get("active_key_id") or keyset.get("active_key") or "").strip()
        )
        if not active_kid:
            import warnings
            warnings.warn("Gateway keyset missing active_kid")
            return None, TrustedKeyStore(), {}

        keys_obj = keyset.get("keys")
        public_only = keyset.get("public_keys")
        if isinstance(public_only, dict) and not isinstance(keys_obj, dict):
            keys_obj = {str(k): {"public_key_hex": str(v)} for k, v in public_only.items()}
        if keys_obj is None:
            keys_obj = {}
        if not isinstance(keys_obj, dict):
            import warnings
            warnings.warn("Gateway keyset 'keys' must be an object")
            return None, TrustedKeyStore(), {}

        active_seed_hex = (keyset.get("active_seed_hex") or keyset.get("seed_hex") or "") or ""
        active_pub_hex = (keyset.get("active_public_key_hex") or keyset.get("public_key_hex") or "") or ""

        for kid, entry in keys_obj.items():
            kid = str(kid)
            if isinstance(entry, str):
                pub0 = entry.strip()
                try:
                    pub0 = _validate_hex_keylen(f"public key for {kid}", pub0, 32)
                except Exception as e:
                    import warnings
                    warnings.warn(f"Invalid public key hex for {kid}: {e}")
                    continue
                public_keys[kid] = pub0
                continue
            if not isinstance(entry, dict):
                continue

            pub = (entry.get("public_key_hex") or entry.get("public") or "") or ""
            pub = str(pub).strip()
            if pub:
                try:
                    pub = _validate_hex_keylen(f"public_key_hex for {kid}", pub, 32)
                    public_keys[kid] = pub
                except Exception as e:
                    import warnings
                    warnings.warn(f"Invalid public key hex for {kid}: {e}")
                    pub = ""

            seed_hex = str(entry.get("seed_hex") or "").strip()
            signing_cmd = str(entry.get("signing_cmd") or "").strip()
            timeout = float(entry.get("timeout_seconds", 2.0) or 2.0)

            if kid == active_kid:
                if seed_hex:
                    try:
                        seed_hex = _validate_hex_keylen(f"seed_hex for {active_kid}", seed_hex, 32)
                        signing_key = Ed25519KeyPair.from_seed(bytes.fromhex(seed_hex), key_id=active_kid)
                        public_keys[active_kid] = signing_key.public_key_hex
                    except Exception as e:
                        import warnings
                        warnings.warn(f"Failed to load active seed_hex for {active_kid}: {e}")
                        signing_key = None
                elif signing_cmd:
                    if not pub:
                        pub = str(active_pub_hex).strip()
                    if pub:
                        pub = _validate_hex_keylen(f"public_key_hex for {active_kid}", pub, 32)
                        signing_key = ExternalEd25519Signer(
                            key_id=active_kid,
                            public_key_bytes=bytes.fromhex(pub),
                            signing_cmd=signing_cmd,
                            timeout_seconds=timeout,
                        )
                        public_keys[active_kid] = pub

        if signing_key is None and str(active_seed_hex).strip():
            try:
                aseed = _validate_hex_keylen(f"active_seed_hex for {active_kid}", str(active_seed_hex).strip(), 32)
                signing_key = Ed25519KeyPair.from_seed(bytes.fromhex(aseed), key_id=active_kid)
                public_keys[active_kid] = signing_key.public_key_hex
            except Exception as e:
                import warnings
                warnings.warn(f"Failed to load top-level active_seed_hex: {e}")
                signing_key = None

        if signing_key is None:
            import warnings
            warnings.warn("Gateway keyset loaded but active signing material is missing")

        store = TrustedKeyStore.from_config(public_keys) if public_keys else TrustedKeyStore()
        return signing_key, store, public_keys

    # Legacy single-key fallback
    kid = (os.getenv("LAP_GATEWAY_SIGNING_KEY_ID", "") or "gateway").strip()
    key_file = os.getenv("LAP_GATEWAY_SIGNING_KEY_FILE", "").strip() or None
    signing_key = load_signing_key(file_path=key_file, key_id=kid, generate_if_missing=allow_ephemeral)
    if signing_key:
        public_keys[signing_key.key_id] = signing_key.public_key_hex
        return signing_key, TrustedKeyStore.from_config(public_keys), public_keys

    if allow_ephemeral:
        signing_key = create_key_pair(kid)
        public_keys[signing_key.key_id] = signing_key.public_key_hex
        return signing_key, TrustedKeyStore.from_config(public_keys), public_keys

    return None, TrustedKeyStore(), {}


def generate_key_file(path: str, key_id: str = "gateway") -> Ed25519KeyPair:
    """
    Generate a new key pair and save seed to file with secure permissions.
    
    HARDENING (v2.0.2): Creates key file with 0600 permissions.
    
    Returns the generated key pair.
    """
    import os
    from pathlib import Path
    
    # Generate key
    key = create_key_pair(key_id)
    
    # Get seed (private key bytes are the seed for Ed25519)
    seed_hex = key.private_key_bytes[:32].hex()
    
    # Write with restricted permissions
    key_path = Path(path)
    
    # Create file with restricted permissions from the start
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, seed_hex.encode('ascii'))
    finally:
        os.close(fd)
    
    return key