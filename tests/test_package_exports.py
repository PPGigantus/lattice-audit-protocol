import importlib


def _read_pyproject_version() -> str:
    import re
    from pathlib import Path

    txt = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r"^version\s*=\s*\"([^\"]+)\"\s*$", txt, flags=re.MULTILINE)
    assert m, "Could not locate [project].version in pyproject.toml"
    return m.group(1)


def test_convenience_imports_work():
    # Ensure top-level convenience imports are available (regression guard)
    import lap_gateway

    # Access via attribute (lazy import)
    assert hasattr(lap_gateway, "LAPGateway")
    assert hasattr(lap_gateway, "create_app")

    # Import directly
    from lap_gateway import LAPGateway, create_app  # noqa: F401

    # Token utilities also exposed
    from lap_gateway import CapabilityToken, TokenIssuer, TokenVerifier  # noqa: F401

    # Ensure module caching works
    importlib.reload(lap_gateway)


def test_version_export_matches_pyproject():
    import lap_gateway

    assert hasattr(lap_gateway, "__version__")
    assert lap_gateway.__version__ == _read_pyproject_version()
