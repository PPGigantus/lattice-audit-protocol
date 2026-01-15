"""Attestation Statement export helpers (PR-003).

This module provides a standards-shaped, schema-first representation of a
tool-invocation receipt as an *attestation statement*.

Design goals:
  - Strict output: only explicit, documented fields (no arbitrary blob dumps).
  - Receipt compatibility: does not change receipts.json formats or verifiers.
  - Binding: when a manifest is available, enforce that action/evidence/decision
    identifiers match (fail closed on mismatches).
"""

from __future__ import annotations

from typing import Any, Dict


ATTESTATION_STATEMENT_TYPE = "https://lattice-audit-protocol.dev/attestation/v1"
PREDICATE_TOOL_INVOCATION_V1 = "https://lattice-audit-protocol.dev/predicate/tool-invocation/v1"


_PREDICATE_FIELDS = [
    # Identity / bindings
    "receipt_id",
    "action_id",
    "evidence_hash",
    "decision_hash",
    "token_jti",
    "sid",
    # Tool invocation details
    "tool_name",
    "operation",
    "params_hash",
    "decision_binding",
    "result_hash",
    "response_hash",
    "result_status",
    # Timing
    "invoked_at_utc",
    "completed_at_utc",
    "duration_ms",
    # Chain integrity
    "prev_receipt_hash",
    "receipt_hash",
    # Signature
    "signature",
    "key_id",
]


def _require_str(d: Dict[str, Any], key: str) -> str:
    v = d.get(key)
    if not isinstance(v, str) or v == "":
        raise ValueError(f"Missing/invalid required string field: {key}")
    return v


def receipt_to_attestation_statement(receipt: Dict[str, Any], manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a receipt + audit-pack manifest into an attestation statement.

    Args:
        receipt: A ToolInvocationReceipt serialized to dict.
        manifest: Audit-pack manifest dict. Used for metadata and binding checks.

    Returns:
        Attestation statement dict (schema-first).

    Raises:
        ValueError: on missing required fields or binding mismatches.
    """

    # Fail-closed binding checks when manifest includes the fields.
    for k in ("action_id", "evidence_hash", "decision_hash"):
        if k in manifest and manifest[k] is not None:
            if receipt.get(k) != manifest.get(k):
                raise ValueError(f"Binding mismatch for {k}: receipt={receipt.get(k)!r} manifest={manifest.get(k)!r}")

    # Subject identity (explicit fields only).
    subject = {
        "action_id": _require_str(receipt, "action_id"),
        "receipt_id": _require_str(receipt, "receipt_id"),
        "tool_name": _require_str(receipt, "tool_name"),
    }

    # Predicate: explicit receipt fields only.
    predicate: Dict[str, Any] = {}
    for field in _PREDICATE_FIELDS:
        if field == "duration_ms":
            # duration_ms is required and must be int
            v = receipt.get(field)
            if not isinstance(v, int):
                raise ValueError("Missing/invalid required integer field: duration_ms")
            predicate[field] = v
            continue

        # receipt_hash is optional in receipts; include only if present and str.
        if field == "receipt_hash":
            v = receipt.get(field)
            if isinstance(v, str) and v != "":
                predicate[field] = v
            continue

        # prev_receipt_hash exists in receipts but can be empty string.
        if field == "prev_receipt_hash":
            v = receipt.get(field)
            if not isinstance(v, str):
                raise ValueError("Missing/invalid required string field: prev_receipt_hash")
            predicate[field] = v
            continue

        predicate[field] = _require_str(receipt, field)


    # Metadata: include explicit fields if available.
    metadata: Dict[str, Any] = {}
    created_at = manifest.get("created_at_utc") or receipt.get("completed_at_utc") or receipt.get("invoked_at_utc")
    if not isinstance(created_at, str) or created_at == "":
        raise ValueError("Missing created_at_utc (manifest) and no usable timestamp in receipt")
    metadata["created_at_utc"] = created_at

    if isinstance(manifest.get("gateway_id"), str) and manifest.get("gateway_id"):
        metadata["gateway_id"] = manifest["gateway_id"]
    if isinstance(manifest.get("protocol_version"), str) and manifest.get("protocol_version"):
        metadata["protocol_version"] = manifest["protocol_version"]

    return {
        "_type": ATTESTATION_STATEMENT_TYPE,
        "subject": [subject],
        "predicateType": PREDICATE_TOOL_INVOCATION_V1,
        "predicate": predicate,
        "metadata": metadata,
    }
