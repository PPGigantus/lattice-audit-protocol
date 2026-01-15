"""LAP Gateway package.

This package provides an enforceable gateway for tool invocations using:

- Signed capability tokens (Ed25519)
- Tiered constraints (T1/T2/T3)
- Replay resistance for higher tiers (nonce + monotonic counter)
- Server-side budget enforcement (atomic reservation)
- Signed receipts and tamper-evident audit logging

Convenience imports
------------------
The package intentionally avoids heavy import-time side effects. For convenience,
these are available as top-level imports:

    from lap_gateway import LAPGateway, create_app

Additional token utilities are also re-exported:

    from lap_gateway import CapabilityToken, TokenIssuer, TokenVerifier

All of the above are loaded lazily.
"""

from __future__ import annotations

import re
from importlib import import_module
from pathlib import Path
from typing import Any


def _read_version_from_pyproject() -> str | None:
    """Best-effort version discovery for dev/test environments.

    We avoid adding runtime TOML dependencies. The project version is a simple
    `version = "..."` field in `pyproject.toml`, so a regex parse is enough.
    """

    try:
        pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
        txt = pyproject.read_text(encoding="utf-8")
        m = re.search(r"^version\s*=\s*\"([^\"]+)\"\s*$", txt, flags=re.MULTILINE)
        return m.group(1) if m else None
    except Exception:
        return None


# Prefer repo-local pyproject version (tests), otherwise fall back to the
# packaged distribution version or a hardcoded default.
__version__ = (
    _read_version_from_pyproject()
    or "1.4.1"
)

# Public symbols we want to make available at the package root.
__all__ = [
    "__version__",
    "LAPGateway",
    "create_app",
    "CapabilityToken",
    "TokenIssuer",
    "TokenVerifier",
]

# Lazy export map: name -> (module, attribute)
_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "LAPGateway": ("lap_gateway.server", "LAPGateway"),
    "create_app": ("lap_gateway.server", "create_app"),
    "CapabilityToken": ("lap_gateway.tokens", "CapabilityToken"),
    "TokenIssuer": ("lap_gateway.tokens", "TokenIssuer"),
    "TokenVerifier": ("lap_gateway.tokens", "TokenVerifier"),
}


def __getattr__(name: str) -> Any:
    if name in _LAZY_EXPORTS:
        module_name, attr = _LAZY_EXPORTS[name]
        module = import_module(module_name)
        value = getattr(module, attr)
        # Cache the resolved attribute on the module for faster future access.
        globals()[name] = value
        return value
    raise AttributeError(f"module 'lap_gateway' has no attribute {name!r}")


def __dir__() -> list[str]:
    # Include lazy exports for IDE/autocomplete.
    return sorted(set(list(globals().keys()) + list(_LAZY_EXPORTS.keys())))
