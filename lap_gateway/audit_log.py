"""Tamper-evident append-only audit log for LAP Gateway.

Implements a JSONL log where each record includes:
- prev_hash: SHA256 of previous record (hex)
- event_hash: SHA256 of canonical event JSON (hex)
- entry_hash: SHA256(prev_hash || event_hash || ts) (hex)
- signature_b64: Ed25519 signature over the canonical payload

This makes after-the-fact tampering detectable.

Note: This does not protect against an attacker who compromises the host and
also controls the signing key. For production, use KMS/HSM for signing keys and
ship logs to a remote append-only store.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .crypto import canonical_json_dumps, Ed25519KeyPair, TrustedKeyStore, _safe_hash_encode, _sha256_hex
from .signing import Signer, coerce_signer


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AuditLogRecord:
    version: str
    ts_utc: str
    prev_hash: str
    event: Dict[str, Any]
    event_hash: str
    entry_hash: str
    key_id: str
    signature_b64: str

    def to_json(self) -> str:
        return json.dumps(
            {
                "version": self.version,
                "ts_utc": self.ts_utc,
                "prev_hash": self.prev_hash,
                "event": self.event,
                "event_hash": self.event_hash,
                "entry_hash": self.entry_hash,
                "key_id": self.key_id,
                "signature_b64": self.signature_b64,
            },
            sort_keys=True,
        )


class TamperEvidentAuditLog:
    """Append-only tamper-evident audit log."""

    def __init__(self, path: str, signer: Signer):
        self.path = str(path)
        self.signer = coerce_signer(signer)
        self._last_hash = "0" * 64

        p = Path(self.path)
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists() and p.stat().st_size > 0:
            # Load last record hash
            try:
                last_line = self._read_last_line(p)
                rec = json.loads(last_line)
                self._last_hash = str(rec.get("entry_hash", self._last_hash))
            except Exception:
                # If log is corrupt, fail closed by keeping last_hash at genesis;
                # verify_file will detect problems.
                self._last_hash = "0" * 64

    @staticmethod
    def _read_last_line(path: Path) -> str:
        with path.open("rb") as f:
            f.seek(0, 2)
            end = f.tell()
            if end == 0:
                return ""
            # Read backwards in chunks until newline
            pos = max(0, end - 4096)
            f.seek(pos)
            chunk = f.read(end - pos)
            lines = chunk.splitlines()
            if not lines:
                return ""
            return lines[-1].decode("utf-8")

    def append_event(self, event: Dict[str, Any], ts_utc: Optional[str] = None) -> AuditLogRecord:
        """Append an event and return the created record."""
        ts = ts_utc or _now_iso()
        event_json = canonical_json_dumps(event, version="v1")
        event_hash = _sha256_hex(event_json.encode("utf-8"))

        entry_hash = _sha256_hex(_safe_hash_encode([self._last_hash, event_hash, ts]))

        payload = _safe_hash_encode(["LAP_AUDIT_V1", ts, self._last_hash, event_hash, entry_hash])
        sig = self.signer.sign(payload)
        sig_b64 = base64.b64encode(sig).decode("ascii")

        rec = AuditLogRecord(
            version="LAP_AUDIT_V1",
            ts_utc=ts,
            prev_hash=self._last_hash,
            event=event,
            event_hash=event_hash,
            entry_hash=entry_hash,
            key_id=self.signer.key_id,
            signature_b64=sig_b64,
        )

        with open(self.path, "a", encoding="utf-8") as f:
            f.write(rec.to_json() + "\n")

        self._last_hash = entry_hash
        return rec

    @staticmethod
    def verify_file(path: str, trusted_keys: TrustedKeyStore) -> Tuple[bool, str, int]:
        """Verify an audit log file. Returns (ok, reason, count)."""
        p = Path(path)
        if not p.exists():
            return True, "NO_FILE", 0

        prev = "0" * 64
        count = 0

        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                count += 1
                try:
                    rec = json.loads(line)
                    version = rec.get("version")
                    if version != "LAP_AUDIT_V1":
                        return False, f"BAD_VERSION:{version}", count
                    ts = str(rec.get("ts_utc"))
                    prev_hash = str(rec.get("prev_hash"))
                    if prev_hash != prev:
                        return False, "CHAIN_BROKEN", count

                    event = rec.get("event")
                    if not isinstance(event, dict):
                        return False, "BAD_EVENT", count

                    event_json = canonical_json_dumps(event, version="v1")
                    event_hash = _sha256_hex(event_json.encode("utf-8"))
                    if event_hash != str(rec.get("event_hash")):
                        return False, "EVENT_HASH_MISMATCH", count

                    expected_entry_hash = _sha256_hex(_safe_hash_encode([prev_hash, event_hash, ts]))
                    if expected_entry_hash != str(rec.get("entry_hash")):
                        return False, "ENTRY_HASH_MISMATCH", count

                    key_id = str(rec.get("key_id"))
                    sig_b64 = str(rec.get("signature_b64"))
                    try:
                        sig = base64.b64decode(sig_b64)
                    except Exception:
                        return False, "BAD_SIGNATURE_ENCODING", count

                    payload = _safe_hash_encode(["LAP_AUDIT_V1", ts, prev_hash, event_hash, expected_entry_hash])
                    if not trusted_keys.verify_signature(key_id, payload, sig, signed_at_utc=ts or None):
                        return False, "INVALID_SIGNATURE", count

                    prev = expected_entry_hash
                except Exception:
                    return False, "PARSE_ERROR", count

        return True, "OK", count
