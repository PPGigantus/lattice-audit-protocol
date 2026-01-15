"""
LAP Gateway Signed Receipts (v2.0)

Audit-grade proof of tool invocations.

Security Properties:
- Ed25519 signed by gateway (unforgeable)
- Bound to action_id + evidence_hash + decision_hash + token_jti
- Contains hashes of tool params and results
- Includes trusted timestamp
- Optionally chain-linked (prev_receipt_hash)

This enables offline verification: an auditor can verify that a specific
tool invocation was authorized by a valid LAP decision, without needing
to trust the gateway's database.
"""

import json
import hashlib
import base64
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

from .crypto import (
    Ed25519KeyPair, TrustedKeyStore, SignedMessage,
    _safe_hash_encode, _sha256_hex, _now_utc,
    canonical_json_dumps
)

from .signing import Signer, coerce_signer


def compute_decision_binding_v1(*, decision_hash: str, token_jti: str, action_id: str, tool_name: str, params_hash: str) -> str:
    """Legacy decision_binding (v1).

    Binds: decision_hash + token_jti + action_id + tool_name + params_hash.
    """
    components = [decision_hash, token_jti, action_id, tool_name, params_hash]
    return _sha256_hex(_safe_hash_encode(components))


def compute_decision_binding(*,
    decision_hash: str,
    token_jti: str,
    action_id: str,
    sid: str,
    tool_name: str,
    operation: str,
    params_hash: str,
    prev_receipt_hash: str,
    evidence_hash: str = "",
) -> str:
    """Compute decision_binding for ToolInvocationReceipt (v2).

    This is the anti-splice / anti-mix-and-match binding primitive.

    Binds:
      - governed decision: decision_hash (and optionally evidence_hash)
      - request identity: action_id
      - session identity: sid
      - authorization identity: token_jti
      - invocation identity: tool_name + operation + params_hash
      - chain identity: prev_receipt_hash
    """
    components = [
        decision_hash,
        token_jti,
        action_id,
        sid,
        tool_name,
        operation,
        params_hash,
        prev_receipt_hash,
    ]
    if evidence_hash:
        components.append(evidence_hash)
    return _sha256_hex(_safe_hash_encode(components))



@dataclass
class ToolInvocationReceipt:
    """
    A signed receipt proving a tool was invoked under LAP governance.
    
    This is audit-grade evidence that:
    1. The tool invocation was authorized by a LAP decision
    2. The specific params were used
    3. The specific result was returned
    4. The invocation happened at a specific time
    
    Receipts can be verified offline without trusting the database.
    """
    # Receipt identity
    receipt_id: str
    
    # Binding to LAP decision
    action_id: str
    evidence_hash: str
    decision_hash: str
    token_jti: str
    
    # Tool invocation details
    tool_name: str
    operation: str
    params_hash: str  # SHA256 of canonical params JSON
    result_hash: str  # SHA256 of canonical tool result JSON
    response_hash: str  # SHA256 of canonical gateway response envelope JSON
    result_status: str  # "success", "error", "timeout"
    
    # Timing
    invoked_at_utc: str
    completed_at_utc: str
    duration_ms: int
    sid: str = ""  # Session id (bound when present)
    decision_binding: str = ""  # SHA256 binding decision↔token↔action↔params
    
    # Chain linking (optional)
    prev_receipt_hash: str = ""
    
    # Signature
    signature: bytes = b""
    key_id: str = ""
    

    def _components_for_payload(self) -> List[str]:
        """Ordered components used for receipt hashing/signing.

        Backwards-compat: decision_binding is included only when present.
        """
        components = [
            self.receipt_id,
            self.action_id,
            self.evidence_hash,
            self.decision_hash,
            self.token_jti,
        ]
        # Backwards-compat: sid is included only when present.
        if self.sid:
            components.append(self.sid)
        components.extend([
            self.tool_name,
            self.operation,
            self.params_hash,
        ])
        if self.decision_binding:
            components.append(self.decision_binding)
        components.extend([
            self.result_hash,
            self.response_hash,
            self.result_status,
            self.invoked_at_utc,
            self.completed_at_utc,
            str(self.duration_ms),
            self.prev_receipt_hash,
        ])
        return components

    def compute_receipt_hash(self) -> str:
        """Compute hash of this receipt (for chaining)."""
        return _sha256_hex(_safe_hash_encode(self._components_for_payload()))
    
    def compute_signature_payload(self) -> bytes:
        """Compute canonical payload for signing."""
        return _safe_hash_encode(self._components_for_payload())
    
    def verify(self, key_store: TrustedKeyStore) -> bool:
        """Verify receipt signature."""
        if not self.signature or not self.key_id:
            return False
        payload = self.compute_signature_payload()
        signed_at = (self.completed_at_utc or self.invoked_at_utc or "")
        return key_store.verify_signature(self.key_id, payload, self.signature, signed_at_utc=signed_at or None)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "action_id": self.action_id,
            "evidence_hash": self.evidence_hash,
            "decision_hash": self.decision_hash,
            "token_jti": self.token_jti,
            "sid": self.sid,
            "tool_name": self.tool_name,
            "operation": self.operation,
            "params_hash": self.params_hash,
            "decision_binding": self.decision_binding,
            "result_hash": self.result_hash,
            "response_hash": self.response_hash,
            "result_status": self.result_status,
            "invoked_at_utc": self.invoked_at_utc,
            "completed_at_utc": self.completed_at_utc,
            "duration_ms": self.duration_ms,
            "prev_receipt_hash": self.prev_receipt_hash,
            "receipt_hash": self.compute_receipt_hash(),
            "signature": base64.b64encode(self.signature).decode('ascii') if self.signature else "",
            "key_id": self.key_id,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolInvocationReceipt":
        return cls(
            receipt_id=data["receipt_id"],
            action_id=data["action_id"],
            evidence_hash=data["evidence_hash"],
            decision_hash=data["decision_hash"],
            token_jti=data["token_jti"],
            sid=data.get("sid", ""),
            tool_name=data["tool_name"],
            operation=data["operation"],
            params_hash=data["params_hash"],
            decision_binding=data.get("decision_binding", ""),
            result_hash=data["result_hash"],
            response_hash=data.get("response_hash", ""),
            result_status=data["result_status"],
            invoked_at_utc=data["invoked_at_utc"],
            completed_at_utc=data["completed_at_utc"],
            duration_ms=data["duration_ms"],
            prev_receipt_hash=data.get("prev_receipt_hash", ""),
            signature=base64.b64decode(data["signature"]) if data.get("signature") else b"",
            key_id=data.get("key_id", ""),
        )
    
    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
    
    @classmethod
    def from_json(cls, json_str: str) -> "ToolInvocationReceipt":
        """Deserialize from JSON string."""
        return cls.from_dict(json.loads(json_str))


class ReceiptIssuer:
    """
    Issues signed receipts for tool invocations.
    
    SECURITY: The issuer holds a signing key. This should be the same
    key (or a different key from the same trust domain) as the token issuer.
    """
    
    def __init__(self, signer: Signer = None, signing_key: Any = None):
        # Backwards-compat: signing_key=... is an alias for signer
        if signer is None and signing_key is not None:
            signer = signing_key
        elif signer is not None and signing_key is not None and signer is not signing_key:
            raise TypeError("Provide either signer or signing_key, not both")
        self.signer = coerce_signer(signer)
        # Receipt chains are action-scoped because audit packs (and offline
        # verification) are action-scoped. A single global chain would cause
        # offline verification to fail whenever a pack contains receipts for a
        # single action while the gateway has issued receipts for other actions.
        self._last_receipt_hash_by_action: Dict[str, str] = {}
        self._receipt_count = 0
    
    def issue_receipt(
        self,
        action_id: str,
        evidence_hash: str,
        decision_hash: str,
        token_jti: str,
        tool_name: str,
        operation: str,
        params: Any,
        result: Any,
        result_status: str,
        invoked_at: datetime,
        completed_at: datetime,
        sid: str = "",
        response_envelope: Optional[Dict[str, Any]] = None,
        chain_receipts: bool = True,
    ) -> ToolInvocationReceipt:
        """
        Issue a signed receipt for a tool invocation.
        """
        import secrets
        
        # Compute hashes of params and result
        def _canon(obj: Any) -> str:
            # Canonical JSON v1 (legacy/permissive) for tool params/results.
            # Tool I/O often contains datetimes/Decimals, so v1 avoids crashes while remaining deterministic.
            return canonical_json_dumps(obj, version="v1")

        # Params are committed in an invocation envelope to prevent tool/op mix-and-match.
        params_env = {"tool_name": tool_name, "operation": operation, "params": params}
        params_json = _canon(params_env)
        result_json = _canon(result)
        response_json = _canon(response_envelope) if response_envelope is not None else result_json
        params_hash = _sha256_hex(params_json.encode('utf-8'))
        result_hash = _sha256_hex(result_json.encode('utf-8'))
        response_hash = _sha256_hex(response_json.encode('utf-8'))
        
        # Calculate duration
        duration_ms = int((completed_at - invoked_at).total_seconds() * 1000)
        
        # Create receipt
        self._receipt_count += 1
        prev_hash = self._last_receipt_hash_by_action.get(action_id, "") if chain_receipts else ""

        decision_binding = compute_decision_binding(
            decision_hash=decision_hash,
            token_jti=token_jti,
            action_id=action_id,
            sid=sid,
            tool_name=tool_name,
            operation=operation,
            params_hash=params_hash,
            prev_receipt_hash=prev_hash,
            evidence_hash=evidence_hash,
        )

        receipt = ToolInvocationReceipt(
            receipt_id=f"rcpt_{secrets.token_urlsafe(12)}_{self._receipt_count}",
            action_id=action_id,
            evidence_hash=evidence_hash,
            decision_hash=decision_hash,
            token_jti=token_jti,
            sid=sid,
            tool_name=tool_name,
            operation=operation,
            params_hash=params_hash,
            decision_binding=decision_binding,
            result_hash=result_hash,
            response_hash=response_hash,
            result_status=result_status,
            invoked_at_utc=invoked_at.isoformat(),
            completed_at_utc=completed_at.isoformat(),
            duration_ms=duration_ms,
            prev_receipt_hash=prev_hash,
            key_id=self.signer.key_id,
        )
        
        # Sign the receipt
        payload = receipt.compute_signature_payload()
        receipt.signature = self.signer.sign(payload)
        
        # Update chain
        if chain_receipts:
            self._last_receipt_hash_by_action[action_id] = receipt.compute_receipt_hash()
        
        return receipt


@dataclass  
class DenialReceipt:
    """
    A signed receipt for a denied or escrowed action.
    
    This proves that the protocol did NOT allow an action,
    which is important for audit trails and compliance.
    """
    receipt_id: str
    action_id: str
    evidence_hash: str
    decision_hash: str
    outcome: str  # "deny", "escrow", "require_external_review"
    tier: str
    reason: str
    denied_at_utc: str
    
    # Signature
    signature: bytes = b""
    key_id: str = ""
    
    def compute_signature_payload(self) -> bytes:
        components = [
            self.receipt_id,
            self.action_id,
            self.evidence_hash,
            self.decision_hash,
            self.outcome,
            self.tier,
            self.reason,
            self.denied_at_utc,
        ]
        return _safe_hash_encode(components)
    
    def verify(self, key_store: TrustedKeyStore) -> bool:
        if not self.signature or not self.key_id:
            return False
        payload = self.compute_signature_payload()
        return key_store.verify_signature(self.key_id, payload, self.signature, signed_at_utc=self.denied_at_utc or None)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "action_id": self.action_id,
            "evidence_hash": self.evidence_hash,
            "decision_hash": self.decision_hash,
            "outcome": self.outcome,
            "tier": self.tier,
            "reason": self.reason,
            "denied_at_utc": self.denied_at_utc,
            "signature": base64.b64encode(self.signature).decode('ascii') if self.signature else "",
            "key_id": self.key_id,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DenialReceipt":
        return cls(
            receipt_id=data["receipt_id"],
            action_id=data["action_id"],
            evidence_hash=data["evidence_hash"],
            decision_hash=data["decision_hash"],
            outcome=data["outcome"],
            tier=data["tier"],
            reason=data["reason"],
            denied_at_utc=data["denied_at_utc"],
            signature=base64.b64decode(data["signature"]) if data.get("signature") else b"",
            key_id=data.get("key_id", ""),
        )


def verify_receipt_file(filepath: str, key_store: TrustedKeyStore) -> tuple[bool, str]:
    """
    Verify a receipt from a JSON file.
    
    Returns (valid, message).
    """
    try:
        with open(filepath) as f:
            data = json.load(f)
        
        # Determine receipt type
        if "tool_name" in data:
            receipt = ToolInvocationReceipt.from_dict(data)
        else:
            receipt = DenialReceipt.from_dict(data)
        
        if receipt.verify(key_store):
            return True, f"Receipt {receipt.receipt_id} signature valid"
        else:
            return False, f"Receipt {receipt.receipt_id} signature INVALID"
    
    except Exception as e:
        return False, f"Failed to verify receipt: {e}"
