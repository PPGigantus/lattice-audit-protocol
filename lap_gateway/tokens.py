"""
LAP Gateway Capability Tokens (v2.0)

Scoped, expiring, budgeted capability tokens for tool invocations.

Security Properties:
- Ed25519 signed (unforgeable by agent)
- Bound to specific action_id + evidence_hash + decision_hash
- Scoped to specific tools and operations
- Budgeted (calls, bytes, spend, time)
- Short-lived (exp claim)
- Single-use or limited-use (jti tracking)

This implements the "capability token" pattern from UAPK-style governance.
"""

import json
import hashlib
import secrets
import base64
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Set
from datetime import datetime, timezone, timedelta
from enum import Enum

from .crypto import (
    canonical_json_dumps,
    Ed25519KeyPair, TrustedKeyStore, SignedMessage,
    _safe_hash_encode, _sha256_hex, _now_utc, CRYPTO_AVAILABLE
)
from .signing import Signer, coerce_signer


class TokenScope(Enum):
    """Predefined scopes for capability tokens."""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    ADMIN = "admin"


@dataclass
class TokenBudget:
    """
    Budget constraints for a capability token.
    
    All fields are optional. None means unlimited.
    Gateway enforces these limits and blocks when exhausted.
    """
    max_calls: Optional[int] = None  # Maximum invocations
    max_bytes_in: Optional[int] = None  # Maximum request payload bytes
    max_bytes_out: Optional[int] = None  # Maximum response payload bytes
    max_spend_cents: Optional[int] = None  # Maximum cost in cents (for paid APIs)
    max_duration_seconds: Optional[int] = None  # Maximum cumulative execution time
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_calls": self.max_calls,
            "max_bytes_in": self.max_bytes_in,
            "max_bytes_out": self.max_bytes_out,
            "max_spend_cents": self.max_spend_cents,
            "max_duration_seconds": self.max_duration_seconds,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenBudget":
        return cls(
            max_calls=data.get("max_calls"),
            max_bytes_in=data.get("max_bytes_in"),
            max_bytes_out=data.get("max_bytes_out"),
            max_spend_cents=data.get("max_spend_cents"),
            max_duration_seconds=data.get("max_duration_seconds"),
        )
    
    @classmethod
    def default_t0(cls) -> "TokenBudget":
        """Default budget for T0 (routine) actions."""
        return cls(max_calls=100, max_bytes_out=10_000_000)
    
    @classmethod
    def default_t1(cls) -> "TokenBudget":
        """Default budget for T1 (sensitive) actions."""
        return cls(max_calls=10, max_bytes_out=1_000_000)
    
    @classmethod
    def default_t2(cls) -> "TokenBudget":
        """Default budget for T2 (high-stakes) actions."""
        return cls(max_calls=3, max_bytes_out=100_000)
    
    @classmethod
    def default_t3(cls) -> "TokenBudget":
        """Default budget for T3 (catastrophic) - single use."""
        return cls(max_calls=1, max_bytes_out=10_000)


@dataclass
class BudgetUsage:
    """Tracks current usage against a budget."""
    calls_used: int = 0
    bytes_in_used: int = 0
    bytes_out_used: int = 0
    spend_cents_used: int = 0
    duration_seconds_used: float = 0.0
    
    def check_budget(self, budget: TokenBudget, 
                     add_calls: int = 1,
                     add_bytes_in: int = 0,
                     add_bytes_out: int = 0,
                     add_spend_cents: int = 0,
                     add_duration: float = 0.0) -> tuple[bool, str]:
        """
        Check if operation fits within budget.
        Returns (allowed, reason).
        """
        if budget.max_calls is not None:
            if self.calls_used + add_calls > budget.max_calls:
                return False, f"BUDGET_EXCEEDED: calls ({self.calls_used + add_calls} > {budget.max_calls})"
        
        if budget.max_bytes_in is not None:
            if self.bytes_in_used + add_bytes_in > budget.max_bytes_in:
                return False, f"BUDGET_EXCEEDED: bytes_in ({self.bytes_in_used + add_bytes_in} > {budget.max_bytes_in})"
        
        if budget.max_bytes_out is not None:
            if self.bytes_out_used + add_bytes_out > budget.max_bytes_out:
                return False, f"BUDGET_EXCEEDED: bytes_out ({self.bytes_out_used + add_bytes_out} > {budget.max_bytes_out})"
        
        if budget.max_spend_cents is not None:
            if self.spend_cents_used + add_spend_cents > budget.max_spend_cents:
                return False, f"BUDGET_EXCEEDED: spend ({self.spend_cents_used + add_spend_cents} > {budget.max_spend_cents})"
        
        if budget.max_duration_seconds is not None:
            if self.duration_seconds_used + add_duration > budget.max_duration_seconds:
                return False, f"BUDGET_EXCEEDED: duration ({self.duration_seconds_used + add_duration:.1f}s > {budget.max_duration_seconds}s)"
        
        return True, "OK"
    
    def record_usage(self,
                     calls: int = 1,
                     bytes_in: int = 0,
                     bytes_out: int = 0,
                     spend_cents: int = 0,
                     duration: float = 0.0) -> None:
        """Record usage."""
        self.calls_used += calls
        self.bytes_in_used += bytes_in
        self.bytes_out_used += bytes_out
        self.spend_cents_used += spend_cents
        self.duration_seconds_used += duration


@dataclass
class CapabilityToken:
    """
    A capability token granting permission to invoke tools.
    
    SECURITY PROPERTIES:
    - Ed25519 signed by gateway (unforgeable)
    - Bound to action_id + evidence_hash + decision_hash
    - Scoped to specific tools and operations
    - Budgeted and time-limited
    - Tracked by jti (JWT ID) for usage enforcement
    
    HARDENING (v2.0.1): Added params_hash for T3 param binding.
    HARDENING (v2.0.2): Added sid (session binding) and nonce support.
    """
    # Core identity
    jti: str  # Unique token ID
    sub: str  # Subject (agent identity)
    iss: str  # Issuer (gateway identity)
    
    # Binding to LAP decision
    action_id: str
    evidence_hash: str
    decision_hash: str
    tier: str  # T0, T1, T2, T3
    
    # Scope and permissions
    allowed_tools: List[str]  # Tool names this token can invoke
    allowed_ops: List[str]  # Operations (read, write, execute, delete)
    
    # Budget and limits
    budget: TokenBudget
    
    # Timing
    iat: str  # Issued at (ISO timestamp)
    exp: str  # Expiration (ISO timestamp)
    
    # Signature
    signature: bytes = b""
    key_id: str = ""
    
    # HARDENING (v2.0.1): Param binding for T3
    params_hash: str = ""  # SHA256 of allowed params (for T3 single-use binding)
    
    # HARDENING (v2.0.2): Session binding and replay prevention
    sid: str = ""  # Session ID (required for T2/T3)
    nonce_required: bool = False  # If True, each invocation must provide unique nonce
    counter_required: bool = False  # If True, invocations must have monotonic counter
    
    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Check if token has expired."""
        now = now or _now_utc()
        try:
            exp_dt = datetime.fromisoformat(self.exp.replace("Z", "+00:00"))
            return now >= exp_dt
        except:
            return True  # Fail closed
    
    def allows_tool(self, tool_name: str) -> bool:
        """Check if token allows invoking a specific tool."""
        if "*" in self.allowed_tools:
            return True
        return tool_name in self.allowed_tools
    
    def allows_op(self, op: str) -> bool:
        """Check if token allows a specific operation."""
        if "*" in self.allowed_ops:
            return True
        return op in self.allowed_ops
    
    def compute_signature_payload(self) -> bytes:
        """Compute canonical payload for signing."""
        components = [
            self.jti,
            self.sub,
            self.iss,
            self.action_id,
            self.evidence_hash,
            self.decision_hash,
            self.tier,
            ",".join(sorted(self.allowed_tools)),
            ",".join(sorted(self.allowed_ops)),
            json.dumps(self.budget.to_dict(), sort_keys=True),
            self.iat,
            self.exp,
            self.params_hash,  # HARDENING (v2.0.1): T3 param binding
            self.sid,  # HARDENING (v2.0.2): Session binding
            str(self.nonce_required),
            str(self.counter_required),
        ]
        return _safe_hash_encode(components)
    
    def verify(self, key_store: TrustedKeyStore) -> bool:
        """Verify token signature."""
        if not self.signature or not self.key_id:
            return False
        payload = self.compute_signature_payload()
        return key_store.verify_signature(self.key_id, payload, self.signature, signed_at_utc=self.iat or None)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "jti": self.jti,
            "sub": self.sub,
            "iss": self.iss,
            "action_id": self.action_id,
            "evidence_hash": self.evidence_hash,
            "decision_hash": self.decision_hash,
            "tier": self.tier,
            "allowed_tools": self.allowed_tools,
            "allowed_ops": self.allowed_ops,
            "budget": self.budget.to_dict(),
            "iat": self.iat,
            "exp": self.exp,
            "signature": base64.b64encode(self.signature).decode('ascii') if self.signature else "",
            "key_id": self.key_id,
            "params_hash": self.params_hash,  # HARDENING (v2.0.1)
            "sid": self.sid,  # HARDENING (v2.0.2)
            "nonce_required": self.nonce_required,
            "counter_required": self.counter_required,
        }
    
    def to_compact(self) -> str:
        """Serialize to compact string format."""
        return base64.urlsafe_b64encode(
            json.dumps(self.to_dict()).encode('utf-8')
        ).decode('ascii')
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CapabilityToken":
        return cls(
            jti=data["jti"],
            sub=data["sub"],
            iss=data["iss"],
            action_id=data["action_id"],
            evidence_hash=data["evidence_hash"],
            decision_hash=data["decision_hash"],
            tier=data["tier"],
            allowed_tools=data["allowed_tools"],
            allowed_ops=data["allowed_ops"],
            budget=TokenBudget.from_dict(data["budget"]),
            iat=data["iat"],
            exp=data["exp"],
            signature=base64.b64decode(data["signature"]) if data.get("signature") else b"",
            key_id=data.get("key_id", ""),
            params_hash=data.get("params_hash", ""),  # HARDENING (v2.0.1)
            sid=data.get("sid", ""),  # HARDENING (v2.0.2)
            nonce_required=data.get("nonce_required", False),
            counter_required=data.get("counter_required", False),
        )
    
    @classmethod
    def from_compact(cls, compact: str) -> "CapabilityToken":
        """Deserialize from compact string format."""
        data = json.loads(base64.urlsafe_b64decode(compact))
        return cls.from_dict(data)


class TokenIssuer:
    """
    Issues capability tokens bound to LAP decisions.
    
    SECURITY: The issuer holds a signing key. In production, this should
    be protected by an HSM or at minimum kept separate from agent access.
    """
    
    # TTL per tier (seconds)
    TIER_TTL = {
        "T0_ROUTINE": 3600,      # 1 hour
        "T1_SENSITIVE": 3600,    # 1 hour
        "T2_HIGH_STAKES": 1800,  # 30 minutes
        "T3_CATASTROPHIC": 300,  # 5 minutes
    }
    
    def __init__(self,
                 issuer_id: str,
                 signer: Signer = None,
                 signing_key: Any = None,
                 default_ttl_seconds: int = 3600):
        self.issuer_id = issuer_id
        # Backwards-compat: signing_key=... is an alias for signer
        if signer is None and signing_key is not None:
            signer = signing_key
        elif signer is not None and signing_key is not None and signer is not signing_key:
            raise TypeError("Provide either signer or signing_key, not both")
        self.signer = coerce_signer(signer)
        self.default_ttl_seconds = default_ttl_seconds
    
    def issue_token(
        self,
        subject: str,  # Agent identity
        action_id: str,
        evidence_hash: str,
        decision_hash: str,
        tier: str,
        allowed_tools: List[str],
        allowed_ops: Optional[List[str]] = None,
        budget: Optional[TokenBudget] = None,
        ttl_seconds: Optional[int] = None,
        params_hash: str = "",  # HARDENING (v2.0.1): T3 param binding
        sid: str = "",  # HARDENING (v2.0.2): Session binding
    ) -> CapabilityToken:
        """
        Issue a new capability token.
        
        The token is bound to a specific action/evidence/decision and grants
        permission to invoke specified tools within budget constraints.
        
        HARDENING (v2.0.1): For T3 tokens, pass params_hash to bind token
        to specific tool invocation parameters.
        
        HARDENING (v2.0.2): For T2/T3 tokens:
        - Session binding (sid) required
        - Nonce required for replay prevention
        - Counter required for ordering (T3 only)
        """
        now = _now_utc()
        
        # TTL based on tier (stricter for higher tiers)
        ttl = ttl_seconds or self.TIER_TTL.get(tier, self.default_ttl_seconds)
        exp = now + timedelta(seconds=ttl)
        
        # Default budget based on tier (always set, never None)
        if budget is None:
            budget_map = {
                "T0_ROUTINE": TokenBudget.default_t0(),
                "T1_SENSITIVE": TokenBudget.default_t1(),
                "T2_HIGH_STAKES": TokenBudget.default_t2(),
                "T3_CATASTROPHIC": TokenBudget.default_t3(),
            }
            budget = budget_map.get(tier, TokenBudget.default_t1())
        
        # HARDENING (v2.0.2): Determine security requirements by tier
        nonce_required = tier in ("T2_HIGH_STAKES", "T3_CATASTROPHIC")
        counter_required = tier == "T3_CATASTROPHIC"
        
        token = CapabilityToken(
            jti=secrets.token_urlsafe(16),
            sub=subject,
            iss=self.issuer_id,
            action_id=action_id,
            evidence_hash=evidence_hash,
            decision_hash=decision_hash,
            tier=tier,
            allowed_tools=allowed_tools,
            allowed_ops=allowed_ops or ["execute"],
            budget=budget,
            iat=now.isoformat(),
            exp=exp.isoformat(),
            key_id=self.signer.key_id,
            params_hash=params_hash,  # HARDENING (v2.0.1)
            sid=sid,  # HARDENING (v2.0.2)
            nonce_required=nonce_required,
            counter_required=counter_required,
        )
        
        # Sign the token
        payload = token.compute_signature_payload()
        token.signature = self.signer.sign(payload)
        
        return token


class BudgetTracker:
    """
    Tracks budget usage per token (by jti).
    
    In production, this should be backed by persistent storage
    (Redis, SQLite, etc.) to survive gateway restarts.
    """
    
    def __init__(self):
        self._usage: Dict[str, BudgetUsage] = {}
        self._revoked: Set[str] = set()
    
    def get_usage(self, jti: str) -> BudgetUsage:
        """Get current usage for a token."""
        if jti not in self._usage:
            self._usage[jti] = BudgetUsage()
        return self._usage[jti]
    
    def check_and_record(
        self,
        token: CapabilityToken,
        bytes_in: int = 0,
        bytes_out: int = 0,
        spend_cents: int = 0,
        duration: float = 0.0,
    ) -> tuple[bool, str]:
        """
        Check if operation is allowed and record usage.
        Returns (allowed, reason).
        """
        if token.jti in self._revoked:
            return False, "TOKEN_REVOKED"
        
        if token.is_expired():
            return False, "TOKEN_EXPIRED"
        
        usage = self.get_usage(token.jti)
        allowed, reason = usage.check_budget(
            token.budget,
            add_calls=1,
            add_bytes_in=bytes_in,
            add_bytes_out=bytes_out,
            add_spend_cents=spend_cents,
            add_duration=duration,
        )
        
        if allowed:
            usage.record_usage(
                calls=1,
                bytes_in=bytes_in,
                bytes_out=bytes_out,
                spend_cents=spend_cents,
                duration=duration,
            )
        
        return allowed, reason
    
    def revoke(self, jti: str) -> None:
        """Revoke a token."""
        self._revoked.add(jti)
    
    def is_revoked(self, jti: str) -> bool:
        """Check if token is revoked."""
        return jti in self._revoked


class TokenVerifier:
    """
    Verifies and validates capability tokens.
    
    Used by the gateway to validate tokens before allowing tool invocations.
    """
    
    def __init__(self, 
                 key_store: TrustedKeyStore,
                 budget_tracker: BudgetTracker):
        self.key_store = key_store
        self.budget_tracker = budget_tracker
    
    def verify_token(
        self,
        token: CapabilityToken,
        required_tool: Optional[str] = None,
        required_op: Optional[str] = None,
        evidence_hash: Optional[str] = None,
    ) -> tuple[bool, str]:
        """
        Verify a token is valid for the requested operation.
        
        Returns (valid, reason).
        """
        # Check signature
        if not token.verify(self.key_store):
            return False, "INVALID_SIGNATURE"
        
        # Check expiration
        if token.is_expired():
            return False, "TOKEN_EXPIRED"
        
        # Check revocation
        if self.budget_tracker.is_revoked(token.jti):
            return False, "TOKEN_REVOKED"
        
        # Check tool permission
        if required_tool and not token.allows_tool(required_tool):
            return False, f"TOOL_NOT_ALLOWED: {required_tool}"
        
        # Check operation permission
        if required_op and not token.allows_op(required_op):
            return False, f"OP_NOT_ALLOWED: {required_op}"
        
        # Check evidence hash binding
        if evidence_hash and token.evidence_hash != evidence_hash:
            return False, f"EVIDENCE_HASH_MISMATCH"
        
        return True, "OK"
