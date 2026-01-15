"""Transparency anchoring utilities.

This module supports local (file) anchoring and optional HTTP push backends.
All network calls are **opt-in** and only used when explicitly configured.


This module defines a tiny append-only interface for "transparency anchors".
An anchor entry is a small JSON object (written as JSONL) containing:
  - timestamp_utc
  - artifact_type (receipt / attestation / auditpack)
  - artifact_hash (sha256 hex)
  - key_id
  - signature (optional)

No external network calls are performed; this is a local file backend.

Hashing policy (PR-006):
  artifact_hash = sha256( canonical_json_v2(artifact) )

We intentionally hash the full artifact object in canonical JSON form,
not the filename, to ensure stable, content-addressed anchors.
"""

from __future__ import annotations

import abc
import hashlib
import json
import urllib.request
import urllib.error
import time
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .crypto import canonical_json_dumps


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()



@dataclass(frozen=True)
class TransparencyPushResult:
    ok: bool
    code: str
    retryable: bool
    http_status: Optional[int]
    attempts: int
    idempotency_key: str
    error: Optional[str] = None



def normalize_dsse_envelope(envelope: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize DSSE envelope for *anchoring*.

    DSSE envelopes may contain multiple signatures; list ordering is not
    semantically meaningful but would affect the anchor hash.

    For anchoring, we sort signatures by keyid (stable) while leaving the
    envelope otherwise unchanged.
    """
    if not isinstance(envelope, dict):
        return envelope  # type: ignore[return-value]
    out: Dict[str, Any] = dict(envelope)
    sigs = out.get("signatures")
    if isinstance(sigs, list):
        def _key(s: Any) -> str:
            if isinstance(s, dict):
                return str(s.get("keyid", ""))
            return ""
        out["signatures"] = sorted(sigs, key=_key)
    return out

def hash_artifact_json(artifact: Any) -> str:
    """Hash an artifact by canonical JSON v2."""
    canonical = canonical_json_dumps(artifact, version="v2")
    return sha256_hex(canonical.encode("utf-8"))


class TransparencyLogger(abc.ABC):
    """Append-only transparency logger interface."""

    @abc.abstractmethod
    def append(self, entry: Dict[str, Any]) -> None:
        raise NotImplementedError


class NullTransparencyLogger(TransparencyLogger):
    """No-op transparency logger."""

    def append(self, entry: Dict[str, Any]) -> None:  # pragma: no cover
        return


class FileTransparencyLogger(TransparencyLogger):
    """Append JSONL entries to a file path."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, entry: Dict[str, Any]) -> None:
        line = json.dumps(entry, separators=(",", ":"), ensure_ascii=False)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line)
            f.write("\n")



# Privacy modes (PR-016)
# - "hash-only": emit only timestamp_utc, artifact_type, artifact_hash
# - "metadata": include key_id, signature, and optional gateway_id
def apply_privacy_mode(entry: Dict[str, Any], mode: str = "hash-only") -> Dict[str, Any]:
    mode = (mode or "hash-only").lower()
    if mode not in ("hash-only", "metadata"):
        raise ValueError(f"Unknown privacy mode: {mode}")
    if mode == "hash-only":
        return {
            "timestamp_utc": entry.get("timestamp_utc"),
            "artifact_type": entry.get("artifact_type"),
            "artifact_hash": entry.get("artifact_hash"),
        }
    # metadata: preserve fields (and omit None values)
    return {k: v for k, v in entry.items() if v is not None}

def make_anchor_entry(
    *,
    artifact_type: str,
    artifact_hash: str,
    key_id: str,
    signature: Optional[str] = None,
    timestamp_utc: Optional[str] = None,
) -> Dict[str, Any]:
    """Create an anchor entry dict conforming to the schema."""
    entry: Dict[str, Any] = {
        "timestamp_utc": timestamp_utc or _now_utc_iso(),
        "artifact_type": artifact_type,
        "artifact_hash": artifact_hash,
        "key_id": key_id,
    }
    if signature is not None:
        entry["signature"] = signature
    return entry


class HttpTransparencyLogger(TransparencyLogger):
    """Optional HTTP backend for pushing anchor entries.

    This backend is **opt-in**. It performs POST requests to the configured URL.
    Failure behavior:
      - if required=True (or ANCHOR_REQUIRED=true), network errors raise RuntimeError (fail closed)
      - otherwise errors are logged and the method returns False.

    The server is expected to accept JSON objects (one per request). If it supports batching,
    use multiple POSTs or wrap entries externally.
    """

    def __init__(self, url: str, *, timeout_s: float = 5.0, required: bool = False, max_attempts: int = 3):
        self.url = url
        self.timeout_s = float(timeout_s)
        self.required = bool(required)
        self.max_attempts = int(max_attempts)
     
    def append(self, entry: Dict[str, Any]) -> bool:
        """
        Push a single transparency anchor entry via HTTP POST.

        Semantics:
          - Adds an Idempotency-Key header (sha256 of canonical JSON v2 of the entry)
          - Treats HTTP 409 Conflict as idempotent success ("already anchored")
          - Retries only retryable failures (timeouts/network/5xx/408/429/502/503/504)

        Returns:
            True on success (including idempotent duplicate), False on failure when not required.

        Raises:
            RuntimeError if required=True and the push does not succeed.
        """
        # Deterministic idempotency key for safe retries.
        idem_key = sha256_hex(canonical_json_dumps(entry, version="v2").encode("utf-8"))
        payload = json.dumps(
            entry,
            separators=(",", ":"),
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")

        last_err: Exception | None = None
        last_status: int | None = None
        last_code: str = "unknown"
        retryable: bool = True

        for attempt in range(1, self.max_attempts + 1):
            headers = {
                "Content-Type": "application/json",
                "Idempotency-Key": idem_key,
                "X-LAP-Attempt": str(attempt),
            }
            req = urllib.request.Request(
                self.url,
                data=payload,
                headers=headers,
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    status = int(getattr(resp, "status", 200))
                    last_status = status
                    if 200 <= status < 300:
                        self.last_result = TransparencyPushResult(
                            ok=True,
                            code="ok",
                            retryable=False,
                            http_status=status,
                            attempts=attempt,
                            idempotency_key=idem_key,
                        )
                        return True
                    # Non-2xx without HTTPError is unusual; treat as permanent failure.
                    last_code = "http_non2xx"
                    retryable = status in {408, 429, 500, 502, 503, 504}
                    last_err = RuntimeError(f"Transparency push failed: HTTP {status}")
            except urllib.error.HTTPError as e:
                status = int(getattr(e, "code", 0) or 0)
                last_status = status or None
                if status == 409:
                    # Idempotent duplicate (already exists).
                    self.last_result = TransparencyPushResult(
                        ok=True,
                        code="duplicate",
                        retryable=False,
                        http_status=status,
                        attempts=attempt,
                        idempotency_key=idem_key,
                    )
                    return True
                retryable = status in {408, 429, 500, 502, 503, 504} or (500 <= status < 600)
                last_code = "retryable_http" if retryable else "permanent_http"
                last_err = e
            except Exception as e:
                # Network errors/timeouts, DNS, etc.
                retryable = True
                last_code = "network_error"
                last_err = e

            if attempt < self.max_attempts and retryable:
                # simple backoff (bounded)
                time.sleep(min(2.0, 0.25 * (2 ** (attempt - 1))))
            else:
                break

        # Failure: record result and possibly raise
        self.last_result = TransparencyPushResult(
            ok=False,
            code=last_code,
            retryable=bool(retryable),
            http_status=last_status,
            attempts=int(attempt),
            idempotency_key=idem_key,
            error=str(last_err) if last_err else None,
        )

        if self.required:
            raise RuntimeError(
                f"Transparency push failed (code={self.last_result.code}, "
                f"retryable={self.last_result.retryable}, http_status={self.last_result.http_status}): "
                f"{self.last_result.error}"
            ) from last_err
        return False




def compute_receipt_anchor_entries(
    receipts: Sequence[Dict[str, Any]],
    *,
    timestamp_utc: Optional[str] = None,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in receipts:
        h = hash_artifact_json(r)
        out.append(
            make_anchor_entry(
                artifact_type="receipt",
                artifact_hash=h,
                key_id=str(r.get("key_id", "")),
                signature=r.get("signature"),
                timestamp_utc=timestamp_utc,
            )
        )
    return out


def compute_dsse_anchor_entry(
    envelope: Dict[str, Any],
    *,
    timestamp_utc: Optional[str] = None,
) -> Dict[str, Any]:
    norm = normalize_dsse_envelope(envelope)
    sigs = norm.get("signatures") or []
    key_id = ""
    sig = None
    if isinstance(sigs, list) and sigs:
        first = sigs[0] or {}
        key_id = str(first.get("keyid", ""))
        sig = first.get("sig")

    return make_anchor_entry(
        artifact_type="attestation",
        artifact_hash=hash_artifact_json(norm),
        key_id=key_id,
        signature=sig,
        timestamp_utc=timestamp_utc,
    )


def _load_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def compute_anchor_entries_for_audit_pack_dir(
    pack_dir: Path,
    *,
    include_receipts: bool = True,
    include_dsse: bool = True,
    timestamp_utc: Optional[str] = None,
    privacy_mode: str = "hash-only",
    gateway_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Compute anchor entries from an extracted audit-pack directory."""
    pack_dir = Path(pack_dir)
    entries: List[Dict[str, Any]] = []

    if include_receipts:
        receipts_path = pack_dir / "receipts.json"
        if receipts_path.exists():
            receipts_obj = _load_json_file(receipts_path)
            if isinstance(receipts_obj, list):
                entries.extend(compute_receipt_anchor_entries(receipts_obj, timestamp_utc=timestamp_utc))
        # If missing, we simply omit; callers may fail closed if desired.

    if include_dsse:
        dsse_path = pack_dir / "attestation.dsse.json"
        if dsse_path.exists():
            env = _load_json_file(dsse_path)
            if isinstance(env, dict):
                entries.append(compute_dsse_anchor_entry(env, timestamp_utc=timestamp_utc))

    if gateway_id:
        for _e in entries:
            if isinstance(_e, dict):
                _e.setdefault("gateway_id", gateway_id)

    entries = [apply_privacy_mode(e, privacy_mode) for e in entries]
    return entries


def compute_anchor_entries_for_audit_pack_zip(
    zip_path: Path,
    *,
    include_receipts: bool = True,
    include_dsse: bool = True,
    include_auditpack_zip_hash: bool = False,
    timestamp_utc: Optional[str] = None,
    privacy_mode: str = "hash-only",
    gateway_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Compute anchor entries from an audit-pack zip.

    For `include_auditpack_zip_hash=True`, we include an `artifact_type="auditpack"`
    entry hashed over the raw zip bytes, using key_id="" and no signature.
    """
    zip_path = Path(zip_path)
    entries: List[Dict[str, Any]] = []

    with tempfile.TemporaryDirectory() as td:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(td)
        entries.extend(
            compute_anchor_entries_for_audit_pack_dir(
                Path(td),
                include_receipts=include_receipts,
                include_dsse=include_dsse,
                timestamp_utc=timestamp_utc,
            )
        )

    if include_auditpack_zip_hash:
        zbytes = zip_path.read_bytes()
        entries.append(
            make_anchor_entry(
                artifact_type="auditpack",
                artifact_hash=sha256_hex(zbytes),
                key_id="",
                signature=None,
                timestamp_utc=timestamp_utc,
            )
        )

    if gateway_id:
        for _e in entries:
            if isinstance(_e, dict):
                _e.setdefault("gateway_id", gateway_id)

    entries = [apply_privacy_mode(e, privacy_mode) for e in entries]
    return entries


# --- Witness interface v1 (PR-024) ---
from .witness import WitnessClient, WitnessResult, NullWitness, FileWitness, HttpWitness  # noqa: E402,F401
