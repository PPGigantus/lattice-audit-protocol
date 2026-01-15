"""
lap_gateway.signing: signing abstraction for gateway artifacts.

This module provides a small interface to support multiple signing backends:
- FileEd25519Signer: in-process signing (dev/testing).
- ExternalCommandSigner: delegates signing to an external command, enabling
  non-exportable private keys (TPM/HSM/enclave/daemon).

Contract for ExternalCommandSigner:
- stdin: base64(message) (may include trailing newline)
- stdout: base64(signature)

All modes are fail-closed: any signer error prevents issuance.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable, Any

from .crypto import Ed25519KeyPair, _run_external_signer_cmd
@runtime_checkable
class Signer(Protocol):
    """Protocol implemented by signing backends."""
    key_id: str
    public_key_bytes: bytes

    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


@dataclass
class FileEd25519Signer:
    """Signer that wraps an Ed25519KeyPair (in-process signing)."""
    keypair: Ed25519KeyPair

    @property
    def key_id(self) -> str:
        return self.keypair.key_id

    @property
    def public_key_bytes(self) -> bytes:
        return self.keypair.public_key_bytes

    @property
    def public_key_hex(self) -> str:
        return self.keypair.public_key_hex

    def sign(self, message: bytes) -> bytes:
        return self.keypair.sign(message)


@dataclass
class ExternalCommandSigner:
    """Signer that delegates to an external signing command.

    This is a "hard-key seam": private keys can live outside the Python process.
    """
    key_id: str
    public_key_bytes: bytes
    signing_cmd: str
    timeout_seconds: float = 2.0

    @property
    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()

    def sign(self, message: bytes) -> bytes:
        return _run_external_signer_cmd(
            signing_cmd=self.signing_cmd,
            message=bytes(message),
            timeout_seconds=self.timeout_seconds,
        )

def coerce_signer(obj: Any) -> Signer:
    """Coerce a supported object into a Signer."""
    if obj is None:
        raise TypeError("signer is None")
    # Already conforms
    if isinstance(obj, (ExternalCommandSigner, FileEd25519Signer, Ed25519KeyPair)):
        if isinstance(obj, Ed25519KeyPair):
            return FileEd25519Signer(obj)
        return obj  # type: ignore[return-value]
    # Duck-typed
    if isinstance(obj, Signer):
        return obj
    raise TypeError(f"Unsupported signer type: {type(obj)}")


def build_signer_from_env(
    base_signer: Any,
    *,
    mode_env: str = "SIGNER_MODE",
    cmd_env: str = "SIGNER_CMD",
    timeout_env: str = "SIGNER_TIMEOUT_SECONDS",
) -> Signer:
    """Build a signer based on environment configuration.

    - SIGNER_MODE=file (default): use base_signer as-is.
    - SIGNER_MODE=external: use ExternalCommandSigner with SIGNER_CMD.
      Public key is taken from base_signer.

    This allows forcing a "hard-key seam" even when the gateway also has a
    software key configured for dev/testing.
    """
    mode = (os.getenv(mode_env, "") or "file").strip().lower()
    # base_signer might be Ed25519KeyPair
    s = coerce_signer(base_signer)

    if mode in ("file", "inproc", "in-process", "software"):
        return s

    if mode in ("external", "cmd", "command"):
        cmd = (os.getenv(cmd_env, "") or "").strip()
        if not cmd:
            raise RuntimeError(f"{cmd_env} must be set when {mode_env}=external")
        tout = (os.getenv(timeout_env, "") or "").strip()
        timeout = 2.0
        if tout:
            try:
                timeout = float(tout)
            except Exception:
                raise RuntimeError(f"{timeout_env} must be a number (seconds)")
        return ExternalCommandSigner(
            key_id=s.key_id,
            public_key_bytes=s.public_key_bytes,
            signing_cmd=cmd,
            timeout_seconds=timeout,
        )

    raise RuntimeError(f"Unsupported {mode_env}={mode!r}; expected file|external")
