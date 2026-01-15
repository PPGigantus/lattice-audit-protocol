"""Witness / transparency interface (v1).

A Witness is an append-only sink for anchor entries. Witnesses can be local
(JSONL file) or remote (HTTP append endpoint). This module provides a stable,
pluggable interface used by the gateway and by integrations.

Idempotency:
- Each append sends an Idempotency-Key header = sha256(canonical_json_v2(entry))
- HTTP 409 is treated as idempotent success (already anchored).

Retry semantics:
- retryable failures: network errors, HTTP 408/429/5xx/502/503/504
- permanent failures: other non-2xx (except 409)

"""

from __future__ import annotations

import abc
import hashlib
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .crypto import canonical_json_dumps_v2
from .errors import (
    LAPError,
    lap_error,
    LAP_E_WITNESS_DUPLICATE,
    LAP_E_WITNESS_NETWORK,
    LAP_E_WITNESS_RETRYABLE_HTTP,
    LAP_E_WITNESS_PERMANENT_HTTP,
)


@dataclass(frozen=True)
class WitnessResult:
    ok: bool
    code: str
    retryable: bool
    http_status: Optional[int]
    attempts: int
    idempotency_key: str
    error: Optional[str] = None


class WitnessClient(abc.ABC):
    """Append-only witness client interface."""

    @abc.abstractmethod
    def append(self, entry: Dict[str, Any]) -> WitnessResult:
        raise NotImplementedError


class NullWitness(WitnessClient):
    def append(self, entry: Dict[str, Any]) -> WitnessResult:  # pragma: no cover
        key = hashlib.sha256(canonical_json_dumps_v2(entry).encode("utf-8")).hexdigest()
        return WitnessResult(ok=True, code="ok", retryable=False, http_status=None, attempts=1, idempotency_key=key)


class FileWitness(WitnessClient):
    """Append entries to a local JSONL file."""

    def __init__(self, path: str):
        self.path = path

    def append(self, entry: Dict[str, Any]) -> WitnessResult:
        key = hashlib.sha256(canonical_json_dumps_v2(entry).encode("utf-8")).hexdigest()
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":"), ensure_ascii=False))
            f.write("\n")
        return WitnessResult(ok=True, code="ok", retryable=False, http_status=None, attempts=1, idempotency_key=key)


class HttpWitness(WitnessClient):
    """Optional HTTP witness backend."""

    def __init__(
        self,
        url: str,
        *,
        timeout_s: float = 5.0,
        required: bool = False,
        max_attempts: int = 3,
        backoff_s: float = 0.25,
    ):
        self.url = url
        self.timeout_s = float(timeout_s)
        self.required = bool(required)
        self.max_attempts = int(max_attempts)
        self.backoff_s = float(backoff_s)
        self.last_result: Optional[WitnessResult] = None

    @staticmethod
    def _is_retryable_status(status: int) -> bool:
        return status in (408, 429, 502, 503, 504) or (500 <= status <= 599)

    def append(self, entry: Dict[str, Any]) -> WitnessResult:
        payload = canonical_json_dumps_v2(entry).encode("utf-8")
        idem_key = hashlib.sha256(payload).hexdigest()

        headers = {
            "Content-Type": "application/json",
            "Idempotency-Key": idem_key,
            "X-LAP-Idempotency-Key": idem_key,
        }

        attempts = 0
        last_err: Optional[str] = None
        last_status: Optional[int] = None

        for attempt in range(1, self.max_attempts + 1):
            attempts = attempt
            headers["X-LAP-Attempt"] = str(attempt)
            req = urllib.request.Request(self.url, data=payload, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    status = int(getattr(resp, "status", 200))
                    last_status = status
                    if 200 <= status <= 299:
                        res = WitnessResult(True, "ok", False, status, attempts, idem_key)
                        self.last_result = res
                        return res
                    if status == 409:
                        res = WitnessResult(True, "duplicate", False, status, attempts, idem_key)
                        self.last_result = res
                        return res

                    if self._is_retryable_status(status) and attempt < self.max_attempts:
                        last_err = f"HTTP {status}"
                        time.sleep(self.backoff_s * (2 ** (attempt - 1)))
                        continue

                    # permanent HTTP failure (or retry exhausted)
                    retryable = self._is_retryable_status(status)
                    code = "retryable_http" if retryable else "permanent_http"
                    res = WitnessResult(False, code, retryable, status, attempts, idem_key, error=f"HTTP {status}")
                    self.last_result = res
                    if self.required:
                        raise lap_error(
                            LAP_E_WITNESS_RETRYABLE_HTTP if retryable else LAP_E_WITNESS_PERMANENT_HTTP,
                            "witness HTTP push failed",
                            retryable=retryable,
                            http_status=status,
                            url=self.url,
                            attempts=attempts,
                            idempotency_key=idem_key,
                        )
                    return res

            except urllib.error.HTTPError as e:
                status = int(getattr(e, "code", 0) or 0)
                last_status = status or None
                if status == 409:
                    res = WitnessResult(True, "duplicate", False, status, attempts, idem_key)
                    self.last_result = res
                    return res
                if status and self._is_retryable_status(status) and attempt < self.max_attempts:
                    last_err = f"HTTP {status}"
                    time.sleep(self.backoff_s * (2 ** (attempt - 1)))
                    continue
                retryable = bool(status and self._is_retryable_status(status))
                code = "retryable_http" if retryable else "permanent_http"
                res = WitnessResult(False, code, retryable, status or None, attempts, idem_key, error=str(e))
                self.last_result = res
                if self.required:
                    raise lap_error(
                        LAP_E_WITNESS_RETRYABLE_HTTP if retryable else LAP_E_WITNESS_PERMANENT_HTTP,
                        "witness HTTP push failed",
                        retryable=retryable,
                        http_status=status or 500,
                        url=self.url,
                        attempts=attempts,
                        idempotency_key=idem_key,
                        error=str(e),
                    )
                return res

            except Exception as e:
                last_err = str(e)
                if attempt < self.max_attempts:
                    time.sleep(self.backoff_s * (2 ** (attempt - 1)))
                    continue
                res = WitnessResult(False, "network_error", True, last_status, attempts, idem_key, error=last_err)
                self.last_result = res
                if self.required:
                    raise lap_error(
                        LAP_E_WITNESS_NETWORK,
                        "witness network error",
                        retryable=True,
                        http_status=503,
                        url=self.url,
                        attempts=attempts,
                        idempotency_key=idem_key,
                        error=last_err,
                    )
                return res

        # Should not reach.
        res = WitnessResult(False, "network_error", True, last_status, attempts, idem_key, error=last_err)
        self.last_result = res
        return res
