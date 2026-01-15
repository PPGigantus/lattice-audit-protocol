"""lap_schema_validate: JSON Schema validation helpers for LAP artifacts.

This module underpins the `lap schema-validate` CLI subcommand.

It validates:
- Individual artifacts (evidence/decision/token/receipt/external approval/manifest)
- Whole audit packs (directory or .zip)

Schemas live in: spec/schemas/

Design notes:
- Uses jsonschema Draft 2020-12.
- Fails closed: schema load errors are treated as validation failures.
"""

from __future__ import annotations

import json
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass
class SchemaMessage:
    ok: bool
    code: str
    detail: str


SCHEMA_FILES: Dict[str, str] = {
    "evidence": "evidence.schema.json",
    "decision": "decision.schema.json",
    "token": "token.schema.json",
    "receipt": "receipt.schema.json",
    "external_approval": "external_approval.schema.json",
    "audit_pack_manifest": "audit_pack_manifest.schema.json",
    "trusted_keys": "trusted_keys.schema.json",
    "trusted_key_registry": "trusted_key_registry.schema.json",
    "profile_attestation": "profile_attestation.schema.json",
    "params": "params.schema.json",
    "attestation_statement": "attestation_statement.schema.json",
    "dsse_envelope": "dsse_envelope.schema.json",
    "transparency_anchor_entry": "transparency_anchor_entry.schema.json",
}


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _default_schemas_dir(repo_root: Optional[Path] = None) -> Path:
    if repo_root is None:
        repo_root = Path(__file__).resolve().parents[0]
    # module is in repo root
    return repo_root / "spec" / "schemas"


def _detect_schema_name(path: Path) -> Optional[str]:
    name = path.name.lower()

    if name in {"profile_attestation.json", "profile_attestation_example.json"}:
        return "profile_attestation"
    if name.startswith("profile_") and name.endswith(".json"):
        # profile_attestations/silver_example.json, etc
        return "profile_attestation"

    if name == "manifest.json":
        return "audit_pack_manifest"
    if name == "trusted_keys.json":
        return "trusted_keys"
    if name in {"key_registry.json", "trusted_key_registry.json", "trusted_keys_registry.json"}:
        return "trusted_key_registry"
    if name.endswith("_key_registry.json"):
        return "trusted_key_registry"
    if name.startswith("evidence") and name.endswith(".json"):
        return "evidence"
    if name.startswith("decision") and name.endswith(".json"):
        return "decision"
    if name.startswith("token") and name.endswith(".json"):
        return "token"
    if name.startswith("external_approval") and name.endswith(".json"):
        return "external_approval"

    # receipts: receipt_basic.json, receipts.json
    if name.startswith("receipt") and name.endswith(".json"):
        return "receipt"
    if name == "receipts.json":
        return "receipt"

    if name.startswith("params") and name.endswith(".json"):
        return "params"

    # Attestation statements (PR-003)
    # Examples: attestation_statement.json, attestation.statement.json
    if name.endswith(".json") and ("attestation_statement" in name or "attestation.statement" in name):
        return "attestation_statement"

    # DSSE-style envelopes (PR-004)
    # Examples: attestation.dsse.json, dsse_envelope.json
    if name.endswith(".json") and ("dsse" in name or name.endswith(".dsse.json") or "dsse_envelope" in name):
        return "dsse_envelope"

    # DSSE envelope streams (rare, but support): *.dsse.jsonl
    if name.endswith(".jsonl") and ("dsse" in name or name.endswith(".dsse.jsonl")):
        return "dsse_envelope"

    # Transparency anchors (PR-006)
    # Examples: anchors.jsonl
    if name == "anchors.jsonl" or (name.endswith(".jsonl") and ("anchors" in name and "anchor" in name)):  # anchors.jsonl
        return "transparency_anchor_entry"

    # Attestation statement streams: attestations.jsonl
    if name.endswith(".jsonl") and (name.startswith("attestations") or "attestation" in name):
        return "attestation_statement"

    return None


def _get_validator(schema_name: str, schemas_dir: Path):
    try:
        import jsonschema
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            "jsonschema is required for schema validation. Install with: pip install jsonschema"
        ) from e

    schema_file = SCHEMA_FILES.get(schema_name)
    if not schema_file:
        raise ValueError(f"Unknown schema: {schema_name}")

    schema_path = schemas_dir / schema_file
    schema = _load_json(schema_path)

    # Draft 2020-12
    return jsonschema.Draft202012Validator(schema)


def validate_instance(
    obj: Any,
    *,
    schema_name: str,
    schemas_dir: Path,
) -> Tuple[bool, List[SchemaMessage]]:
    msgs: List[SchemaMessage] = []
    try:
        validator = _get_validator(schema_name, schemas_dir)
        errors = sorted(validator.iter_errors(obj), key=lambda e: list(e.absolute_path))
        if errors:
            for e in errors[:50]:
                loc = "/".join(str(p) for p in e.absolute_path)
                loc = loc or "<root>"
                msgs.append(SchemaMessage(False, "SCHEMA_ERROR", f"{schema_name} {loc}: {e.message}"))
            if len(errors) > 50:
                msgs.append(
                    SchemaMessage(False, "SCHEMA_ERROR", f"{schema_name}: {len(errors) - 50} more errors...")
                )
            return False, msgs
        msgs.append(SchemaMessage(True, "SCHEMA_OK", f"{schema_name}: valid"))
        return True, msgs
    except FileNotFoundError as e:
        return False, [SchemaMessage(False, "SCHEMA_MISSING", str(e))]
    except Exception as e:
        return False, [SchemaMessage(False, "SCHEMA_VALIDATE_EXCEPTION", str(e))]


def validate_file(
    path: Path,
    *,
    schema_name: Optional[str] = None,
    schemas_dir: Optional[Path] = None,
) -> Tuple[bool, List[SchemaMessage]]:
    schemas_dir = schemas_dir or _default_schemas_dir()
    schema_name = schema_name or _detect_schema_name(path)

    if not schema_name:
        return False, [SchemaMessage(False, "SCHEMA_UNDETECTED", f"Cannot infer schema for {path.name}. Use --schema.")]

    # JSONL support for streams of statements (one JSON object per line)
    if path.suffix.lower() == ".jsonl":
        schema_name = schema_name or _detect_schema_name(path)
        if not schema_name:
            return False, [SchemaMessage(False, "SCHEMA_UNDETECTED", f"Cannot infer schema for {path.name}. Use --schema.")]

        ok_all = True
        out_msgs: List[SchemaMessage] = []
        with path.open("r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception as e:
                    ok_all = False
                    out_msgs.append(SchemaMessage(False, "JSONL_PARSE_ERROR", f"line[{i}]: {e}"))
                    continue
                ok, msgs = validate_instance(obj, schema_name=schema_name, schemas_dir=schemas_dir)
                ok_all = ok_all and ok
                for m in msgs:
                    if m.ok:
                        continue
                    out_msgs.append(SchemaMessage(False, m.code, f"line[{i}]: {m.detail}"))

        if ok_all:
            return True, [SchemaMessage(True, "SCHEMA_OK", f"{path.name}: all lines valid")]
        return False, out_msgs

    obj = _load_json(path)

    # receipts.json is a list of receipts
    if path.name.lower() == "receipts.json":
        if not isinstance(obj, list):
            return False, [SchemaMessage(False, "SCHEMA_ERROR", "receipts.json must be a list")]
        ok_all = True
        out_msgs: List[SchemaMessage] = []
        for i, item in enumerate(obj):
            ok, msgs = validate_instance(item, schema_name=schema_name, schemas_dir=schemas_dir)
            ok_all = ok_all and ok
            for m in msgs:
                if m.ok:
                    continue
                out_msgs.append(SchemaMessage(False, m.code, f"receipt[{i}]: {m.detail}"))
        if ok_all:
            return True, [SchemaMessage(True, "SCHEMA_OK", "receipts.json: all receipts valid")]
        return False, out_msgs

    return validate_instance(obj, schema_name=schema_name, schemas_dir=schemas_dir)


def validate_audit_pack_dir(
    pack_dir: Path,
    *,
    schemas_dir: Optional[Path] = None,
    strict: bool = False,
) -> Tuple[bool, List[SchemaMessage]]:
    """Validate a full audit pack directory.

    strict=False: missing optional files are not errors.
    strict=True: missing optional files are errors.
    """

    schemas_dir = schemas_dir or _default_schemas_dir()
    msgs: List[SchemaMessage] = []

    required = [
        ("manifest.json", "audit_pack_manifest"),
        ("evidence.json", "evidence"),
        ("decision.json", "decision"),
        ("receipts.json", "receipt"),
        ("trusted_keys.json", "trusted_keys"),
    ]
    optional = [
        ("token.json", "token"),
        ("external_approval.json", "external_approval"),
        ("anchor.json", None),
        ("invocations.json", None),
        ("verify.py", None),
        ("VERIFY.md", None),
    ]

    ok_all = True

    for fname, schema in required:
        p = pack_dir / fname
        if not p.exists():
            ok_all = False
            msgs.append(SchemaMessage(False, "PACK_MISSING_REQUIRED", f"missing: {fname}"))
            continue
        if schema is None:
            msgs.append(SchemaMessage(True, "PACK_PRESENT", f"present: {fname}"))
            continue
        ok, m = validate_file(p, schema_name=schema, schemas_dir=schemas_dir)
        ok_all = ok_all and ok
        msgs.extend(m)

    for fname, schema in optional:
        p = pack_dir / fname
        if not p.exists():
            if strict:
                ok_all = False
                msgs.append(SchemaMessage(False, "PACK_MISSING_OPTIONAL", f"missing (strict): {fname}"))
            continue
        if schema is None:
            msgs.append(SchemaMessage(True, "PACK_PRESENT", f"present: {fname}"))
            continue
        ok, m = validate_file(p, schema_name=schema, schemas_dir=schemas_dir)
        ok_all = ok_all and ok
        msgs.extend(m)

    return ok_all, msgs


def validate_path(
    path: Path,
    *,
    schema_name: Optional[str] = None,
    schemas_dir: Optional[Path] = None,
    strict: bool = False,
) -> Tuple[bool, List[SchemaMessage]]:
    """Validate a file, audit-pack dir, or audit-pack zip."""

    if not path.exists():
        return False, [SchemaMessage(False, "NOT_FOUND", str(path))]

    schemas_dir = schemas_dir or _default_schemas_dir()

    if path.is_dir():
        return validate_audit_pack_dir(path, schemas_dir=schemas_dir, strict=strict)

    if path.suffix.lower() == ".zip":
        with tempfile.TemporaryDirectory() as td:
            with zipfile.ZipFile(path, "r") as zf:
                zf.extractall(td)
            return validate_audit_pack_dir(Path(td), schemas_dir=schemas_dir, strict=strict)

    return validate_file(path, schema_name=schema_name, schemas_dir=schemas_dir)


def list_schemas() -> List[str]:
    return sorted(SCHEMA_FILES.keys())


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for `python -m lap_schema_validate`.

    This is intentionally minimal; the richer UX lives under `lap schema-validate`.
    """

    import argparse

    parser = argparse.ArgumentParser(prog="lap_schema_validate")
    parser.add_argument("path", help="Path to a LAP artifact, audit-pack dir, or audit-pack .zip")
    parser.add_argument("--schema", dest="schema", default=None, help="Override schema name")
    parser.add_argument(
        "--schemas-dir",
        dest="schemas_dir",
        default=None,
        help="Directory containing schema files (default: spec/schemas)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Strict mode for audit packs (reject unknown files)",
    )
    parser.add_argument(
        "--list-schemas",
        action="store_true",
        help="List supported schema names and exit",
    )

    args = parser.parse_args(argv)

    if args.list_schemas:
        for name in list_schemas():
            print(name)
        return 0

    ok, messages = validate_path(
        Path(args.path),
        schema_name=args.schema,
        schemas_dir=Path(args.schemas_dir) if args.schemas_dir else None,
        strict=args.strict,
    )

    for m in messages:
        prefix = "OK" if m.ok else "FAIL"
        print(f"{prefix} {m.code}: {m.detail}")
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())