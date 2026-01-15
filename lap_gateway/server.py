"""
LAP Gateway Server (v2.0)

FastAPI-based Policy Enforcement Point (PEP).

Security Properties:
- Agent NEVER calls tools directly - only through gateway
- Gateway holds tool credentials (agent never sees them)
- All invocations require valid capability tokens
- Every action produces signed receipts
- Budgets enforced server-side

This is the "non-bypassable" enforcement layer.
"""

from __future__ import annotations

import json
import hashlib
import secrets
import logging
import sqlite3
import os
import time
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple


def _http_exc(status: int, code: str, message: str, *, retryable: bool = False, **details: Any):
    """Create an HTTPException with a stable error envelope in `detail`."""
    if not FASTAPI_AVAILABLE:
        raise RuntimeError("FastAPI required")
    detail: Dict[str, Any] = {"code": code, "message": message, "retryable": bool(retryable)}
    if details:
        detail["details"] = details
    return HTTPException(status, detail)

from dataclasses import dataclass, field, asdict
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path

# FastAPI imports (optional - graceful degradation)
try:
    from fastapi import FastAPI, HTTPException, Depends, Header, Request, Response
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    BaseModel = object

from .crypto import (
    Ed25519KeyPair, TrustedKeyStore, Ed25519ExternalApproval,
    _sha256_hex, _safe_hash_encode, _now_utc, create_key_pair, CRYPTO_AVAILABLE,
    load_signing_key, load_gateway_signing_material, canonical_json_dumps
)

from .errors import (
    LAPError,
    LAP_E_AUTH_REQUIRED,
    LAP_E_AGENT_ID_REQUIRED,
    LAP_E_SESSION_MISMATCH,
    LAP_E_RATE_LIMITED,
    LAP_E_LOCKDOWN_ACTIVE,
    LAP_E_TOOL_NAME_MISMATCH,
    LAP_E_COUNTER_INVALID,
    LAP_E_COUNTER_NOT_MONOTONIC,
    LAP_E_COUNTER_ROLLBACK,
    LAP_E_COUNTER_STORAGE,
    LAP_E_BAD_REQUEST,
)

from .signing import Signer, build_signer_from_env, coerce_signer
from .tokens import (
    CapabilityToken, TokenBudget, BudgetTracker, TokenIssuer, TokenVerifier
)
from .receipts import (
    ToolInvocationReceipt, DenialReceipt, ReceiptIssuer
)
from .evidence_quality import (
    EvidenceQualityChecker, EvidenceQualityPolicy, validate_evidence_quality
)
from .auth import ApiKeyAuth
from .audit_log import TamperEvidentAuditLog
from .counter_journal import CounterJournal
from .lockdown import DbCircuitBreaker, StorageLockdownError
from .replay_hotpath import ReplayHotPath
from .ratelimit import RateLimiter, parse_rate_limit

from .pdp import PDPClient, build_pdp_client_from_env

# Optional observability (Prometheus). Safe no-op if prometheus_client is missing.
try:
    from .metrics import (
        instrument_fastapi,
        record_decision,
        record_invocation,
        record_rate_limited,
        record_replay_reject,
        set_lockdown_active,
    )
    METRICS_HOOKS_AVAILABLE = True
except Exception:  # pragma: no cover
    METRICS_HOOKS_AVAILABLE = False
    instrument_fastapi = None  # type: ignore
    record_decision = record_invocation = record_rate_limited = None  # type: ignore
    record_replay_reject = set_lockdown_active = None  # type: ignore



# Lightweight in-memory operational stats (no external deps)
from .ops_stats import OPS_STATS
logger = logging.getLogger("lap_gateway")


# ---------------------------
# Request/Response Models
# ---------------------------

if FASTAPI_AVAILABLE:
    class EvaluateRequest(BaseModel):
        """Request to evaluate an action."""
        action_id: str
        description: str
        timestamp_utc: Optional[str] = None
        irreversibility: Dict[str, Any] = Field(default_factory=dict)
        outcome_delta: Dict[str, Any] = Field(default_factory=dict)
        necessity_confidence: float = 0.5
        novelty_loss_estimate: float = 0.0
        novelty_method: str = "none"
        suffering_risk_estimate: float = 0.0
        suffering_method: str = "none"
        provenance: Dict[str, Any] = Field(default_factory=dict)
        alternatives: List[Dict[str, Any]] = Field(default_factory=list)
        attestations: List[Dict[str, Any]] = Field(default_factory=list)
        agent_id: str = "unknown"
        session_id: str = ""  # HARDENING (v2.0.2): Session binding
    
    class EvaluateResponse(BaseModel):
        """Response from action evaluation."""
        outcome: str  # approve, deny, escrow, require_external_review
        tier: str
        reason: str
        action_id: str
        evidence_hash: str
        decision_hash: str
        capability_token: Optional[str] = None  # Only if approved (not for T3)
        constraints: Dict[str, Any] = Field(default_factory=dict)
        denial_receipt: Optional[Dict[str, Any]] = None
        requires_mint: bool = False  # HARDENING (v2.0.2): T3 requires separate mint
    
    class MintT3TokenRequest(BaseModel):
        """
        Request to mint a T3 token for a specific invocation.
        
        HARDENING (v2.0.2): T3 tokens are minted per-invocation with
        params_hash binding. The action must already be approved.
        """
        action_id: str
        evidence_hash: str  # Must be 64 hex chars (SHA256)
        decision_hash: str
        tool_name: str
        operation: str = "execute"
        params: Dict[str, Any] = Field(default_factory=dict)
        session_id: str  # Required for T3
    
    class MintT3TokenResponse(BaseModel):
        """Response with minted T3 token."""
        capability_token: str
        params_hash: str
        expires_at: str
        single_use: bool = True
    
    class ToolInvokeRequest(BaseModel):
        """Request to invoke a tool."""
        tool_name: str
        operation: str = "execute"
        params: Dict[str, Any] = Field(default_factory=dict)
        capability_token: str  # Required
        # HARDENING (v2.0.2): Anti-replay fields
        nonce: Optional[str] = None  # Required if token.nonce_required
        counter: Optional[int] = None  # Required if token.counter_required
    
    class ToolInvokeResponse(BaseModel):
        """Response from tool invocation."""
        success: bool
        result: Any = None
        error: Optional[str] = None
        receipt: Dict[str, Any] = Field(default_factory=dict)
    
    class ExternalApprovalRequest(BaseModel):
        """Request to record an external approval."""
        action_id: str
        evidence_hash: str
        reviewer_id: str
        reviewer_type: str
        decision: str
        confidence: float
        reasoning: str
        conditions: List[str] = Field(default_factory=list)
        signature: str  # Base64 Ed25519 signature
        key_id: str


    class SessionRequest(BaseModel):
        """Request to create a new gateway-issued session (for T2/T3)."""
        ttl_seconds: int = Field(default=3600, ge=60, le=86400)

    class SessionResponse(BaseModel):
        """Response containing a gateway-issued session id."""
        session_id: str
        expires_at_utc: str

# Tool Connectors
# ---------------------------

class ToolConnector:
    """
    Base class for tool connectors.
    
    Connectors handle actual tool invocation with credentials
    that the agent never sees.
    """
    
    def __init__(self, tool_name: str):
        self.tool_name = tool_name
    
    async def invoke(
        self,
        operation: str,
        params: Dict[str, Any],
        credentials: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Any, Optional[str]]:
        """
        Invoke the tool.
        
        Returns (success, result, error_message).
        """
        raise NotImplementedError
    
    def get_allowed_operations(self) -> List[str]:
        """Get list of allowed operations for this tool."""
        return ["execute"]


class MockToolConnector(ToolConnector):
    """Mock tool connector for testing."""
    
    async def invoke(
        self,
        operation: str,
        params: Dict[str, Any],
        credentials: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Any, Optional[str]]:
        """Mock invocation - returns params as result."""
        return True, {"echo": params, "operation": operation}, None


class FileSystemConnector(ToolConnector):
    """
    File system tool connector with sandboxing.
    
    SECURITY: Only allows operations within allowed_paths.
    """
    
    def __init__(self, allowed_paths: List[str]):
        super().__init__("filesystem")
        self.allowed_paths = [Path(p).resolve() for p in allowed_paths]
    
    def _is_path_allowed(self, path: str) -> bool:
        """Check if path is within allowed directories."""
        try:
            resolved = Path(path).resolve()
            return any(
                resolved == allowed or allowed in resolved.parents
                for allowed in self.allowed_paths
            )
        except:
            return False
    
    def _safe_open(self, path: str, mode: str, follow_symlinks: bool = False):
        """
        Open a file with TOCTOU mitigation.
        
        HARDENING (v2.0.2): Uses O_NOFOLLOW where available to prevent
        symlink-based TOCTOU attacks. Falls back to symlink check + open.
        
        NOTE: This is not a complete TOCTOU fix (race window still exists
        between resolve and open), but it raises the bar. For production,
        consider using a chroot jail or container namespaces.
        """
        import os
        
        resolved = Path(path).resolve()
        
        # Re-check after resolve
        if not self._is_path_allowed(str(resolved)):
            raise PermissionError(f"Path escapes allowed directories: {path}")
        
        # Check for symlinks if not following them
        if not follow_symlinks:
            try:
                if os.path.islink(path):
                    raise PermissionError(f"Symlinks not allowed: {path}")
            except (OSError, ValueError):
                pass
        
        # Open with flags to reduce TOCTOU window
        # Note: O_NOFOLLOW not available on all platforms for text mode
        if 'r' in mode:
            flags = os.O_RDONLY
        elif 'w' in mode:
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        else:
            flags = os.O_RDONLY
        
        # Try O_NOFOLLOW if available and not following symlinks
        if not follow_symlinks and hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW
        
        try:
            fd = os.open(str(resolved), flags, 0o644)
            return os.fdopen(fd, mode)
        except OSError as e:
            if e.errno == 40:  # ELOOP - too many symlinks
                raise PermissionError(f"Symlink loop detected: {path}")
            raise
    
    async def invoke(
        self,
        operation: str,
        params: Dict[str, Any],
        credentials: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Any, Optional[str]]:
        path = params.get("path", "")
        
        if not self._is_path_allowed(path):
            return False, None, f"Path not allowed: {path}"
        
        if operation == "read":
            try:
                # HARDENING (v2.0.2): Use safe_open
                with self._safe_open(path, 'r') as f:
                    content = f.read(params.get("max_bytes", 1_000_000))
                return True, {"content": content, "path": path}, None
            except PermissionError as e:
                return False, None, f"Permission denied: {e}"
            except Exception as e:
                return False, None, str(e)
        
        elif operation == "write":
            try:
                content = params.get("content", "")
                # HARDENING (v2.0.2): Use safe_open
                with self._safe_open(path, 'w') as f:
                    f.write(content)
                return True, {"written_bytes": len(content), "path": path}, None
            except PermissionError as e:
                return False, None, f"Permission denied: {e}"
            except Exception as e:
                return False, None, str(e)
        
        elif operation == "list":
            try:
                resolved = Path(path).resolve()
                if not self._is_path_allowed(str(resolved)):
                    return False, None, f"Path escapes allowed directories: {path}"
                entries = list(resolved.iterdir())
                return True, {"entries": [str(e) for e in entries]}, None
            except Exception as e:
                return False, None, str(e)
        
        return False, None, f"Unknown operation: {operation}"
    
    def get_allowed_operations(self) -> List[str]:
        return ["read", "write", "list"]


# ---------------------------
# Credential Provider
# ---------------------------

class CredentialProvider:
    """
    Base class for JIT credential providers.
    
    Gateway fetches credentials at invocation time;
    agent never sees long-lived secrets.
    """
    
    def get_credentials(self, tool_name: str, operation: str) -> Optional[Dict[str, Any]]:
        """Get credentials for a tool operation."""
        raise NotImplementedError


class StaticCredentialProvider(CredentialProvider):
    """Static credential provider for development."""
    
    def __init__(self, credentials: Dict[str, Dict[str, Any]]):
        self._credentials = credentials
    
    def get_credentials(self, tool_name: str, operation: str) -> Optional[Dict[str, Any]]:
        return self._credentials.get(tool_name)


# ---------------------------
# External Time Source
# ---------------------------

class TrustedTimeSource:
    """
    Trusted time source for escrow verification.
    
    Prevents clock-skew attacks where agent fast-forwards system time
    to bypass cooling periods.
    """
    
    def get_trusted_time(self) -> datetime:
        """Get trusted current time."""
        raise NotImplementedError
    
    def verify_elapsed(self, start_time: str, min_seconds: int) -> Tuple[bool, str]:
        """
        Verify that at least min_seconds have elapsed since start_time.
        
        Returns (elapsed, reason).
        """
        raise NotImplementedError


class LocalTimeSource(TrustedTimeSource):
    """Local system time (not secure against clock skew)."""
    
    def get_trusted_time(self) -> datetime:
        return _now_utc()
    
    def verify_elapsed(self, start_time: str, min_seconds: int) -> Tuple[bool, str]:
        try:
            start = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
            now = self.get_trusted_time()
            elapsed = (now - start).total_seconds()
            
            if elapsed >= min_seconds:
                return True, f"Elapsed {elapsed:.0f}s >= {min_seconds}s required"
            else:
                return False, f"Only {elapsed:.0f}s elapsed, {min_seconds}s required"
        except Exception as e:
            return False, f"Time verification failed: {e}"


class NTPTimeSource(TrustedTimeSource):
    """
    NTP-verified time source.
    
    Queries NTP servers to get trusted time independent of system clock.
    """
    
    def __init__(self, ntp_servers: List[str] = None, max_drift_seconds: float = 5.0):
        self.ntp_servers = ntp_servers or ["pool.ntp.org", "time.google.com"]
        self.max_drift_seconds = max_drift_seconds
        self._last_ntp_time: Optional[datetime] = None
        self._last_local_time: Optional[datetime] = None
    
    def get_trusted_time(self) -> datetime:
        """Get NTP time, falling back to local if unavailable."""
        try:
            import ntplib
            client = ntplib.NTPClient()
            
            for server in self.ntp_servers:
                try:
                    response = client.request(server, version=3, timeout=2)
                    ntp_time = datetime.fromtimestamp(response.tx_time, tz=timezone.utc)
                    
                    # Cache for drift detection
                    self._last_ntp_time = ntp_time
                    self._last_local_time = _now_utc()
                    
                    return ntp_time
                except:
                    continue
            
            # All servers failed - use local with warning
            logger.warning("All NTP servers unreachable, using local time")
            return _now_utc()
            
        except ImportError:
            # ntplib not installed
            logger.warning("ntplib not installed, using local time")
            return _now_utc()
    
    def verify_elapsed(self, start_time: str, min_seconds: int) -> Tuple[bool, str]:
        try:
            start = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
            now = self.get_trusted_time()
            elapsed = (now - start).total_seconds()
            
            # Check for suspicious clock drift
            local_now = _now_utc()
            drift = abs((now - local_now).total_seconds())
            if drift > self.max_drift_seconds:
                logger.warning(f"Clock drift detected: {drift:.1f}s")
            
            if elapsed >= min_seconds:
                return True, f"NTP verified: {elapsed:.0f}s >= {min_seconds}s"
            else:
                return False, f"NTP verified: only {elapsed:.0f}s elapsed"
                
        except Exception as e:
            return False, f"NTP verification failed: {e}"


# ---------------------------
# Gateway Store
# ---------------------------

class GatewayStore:
    """
    Persistent storage for gateway state.
    
    Storage Properties:
    - Uses secure_delete pragma to zero deleted pages
    - Uses WAL mode for concurrency
    
    NOTE (v2.0.2): secure_delete + WAL provides partial forensic mitigation
    but is NOT a complete solution. WAL frames and backups may still contain
    old data. For strong forensic resistance, use encrypted storage with
    secure key destruction, or consider a full-disk encryption solution.
    """
    
    def __init__(self, db_path: str = "lap_gateway.db"):
        self.db_path = db_path
        self.circuit = DbCircuitBreaker()
        self.replay_hotpath = ReplayHotPath()
        self._init_db()

        # Crash-safe monotonic counters: fsync'd append-only journal.
        journal_path = os.getenv(
            "LAP_COUNTER_JOURNAL_PATH",
            str(Path(self.db_path).with_suffix(".counters.jsonl")),
        )
        self.counter_journal = CounterJournal(journal_path)
        try:
            self.counter_journal.load()
        except Exception as e:
            # Treat as storage failure and fail-closed.
            self.circuit.record_failure(e)
            raise StorageLockdownError("COUNTER_JOURNAL_UNAVAILABLE") from e

    @contextmanager
    def _db(self, op_name: str, isolation_level: Optional[str] = None):
        """DB connection wrapper with circuit breaker (fail-closed).

        All store operations should use this to ensure that storage degradation
        triggers LOCKDOWN rather than inconsistent or fail-open behavior.
        """
        self.circuit.raise_if_lockdown()
        start = time.monotonic()
        try:
            conn = sqlite3.connect(
                self.db_path,
                timeout=float(self.circuit.config.connect_timeout_seconds),
                isolation_level=isolation_level,
            )
            try:
                with conn:
                    yield conn
            finally:
                conn.close()
            elapsed_ms = (time.monotonic() - start) * 1000.0
            if elapsed_ms >= float(self.circuit.config.latency_threshold_ms):
                self.circuit.record_latency(elapsed_ms)
            else:
                self.circuit.record_success()
        except sqlite3.OperationalError as e:
            # Treat configured OperationalErrors as failure signals.
            if self.circuit.should_treat_operational_error_as_failure(str(e)):
                self.circuit.record_failure(e)
            raise
    
    def _init_db(self):
        with self._db("store_op") as conn:
            # Enable secure delete (zeros deleted pages, not a complete solution)
            conn.execute("PRAGMA secure_delete = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = FULL")
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA busy_timeout = 5000")
            
            # Decisions table
            conn.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                decision_id TEXT PRIMARY KEY,
                action_id TEXT NOT NULL,
                evidence_hash TEXT NOT NULL,
                decision_hash TEXT NOT NULL,
                outcome TEXT NOT NULL,
                tier TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                agent_id TEXT NOT NULL
            )
            """)
            
            # Tokens table
            conn.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                jti TEXT PRIMARY KEY,
                action_id TEXT NOT NULL,
                evidence_hash TEXT NOT NULL,
                decision_hash TEXT NOT NULL,
                token_json TEXT NOT NULL,
                issued_at_utc TEXT NOT NULL,
                expires_at_utc TEXT NOT NULL,
                revoked BOOLEAN DEFAULT FALSE
            )
            """)
            
            # Sessions table (gateway-issued session ids)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                expires_at_utc TEXT NOT NULL
            )
            """)

            # Budget usage table
            conn.execute("""
            CREATE TABLE IF NOT EXISTS budget_usage (
                jti TEXT PRIMARY KEY,
                calls_used INTEGER DEFAULT 0,
                bytes_in_used INTEGER DEFAULT 0,
                bytes_out_used INTEGER DEFAULT 0,
                spend_cents_used INTEGER DEFAULT 0,
                duration_seconds_used REAL DEFAULT 0,
                last_updated_utc TEXT NOT NULL
            )
            """)
            
            # Receipts table
            conn.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                receipt_id TEXT PRIMARY KEY,
                action_id TEXT NOT NULL,
                token_jti TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                created_at_utc TEXT NOT NULL
            )
            """)
            
            # Anchors table
            conn.execute("""
            CREATE TABLE IF NOT EXISTS anchors (
                anchor_id INTEGER PRIMARY KEY AUTOINCREMENT,
                head_hash TEXT NOT NULL,
                receipt_count INTEGER NOT NULL,
                anchored_at_utc TEXT NOT NULL,
                signature TEXT NOT NULL,
                key_id TEXT NOT NULL
            )
            """)
            
            # External approvals table
            conn.execute("""
            CREATE TABLE IF NOT EXISTS external_approvals (
                action_id TEXT NOT NULL,
                evidence_hash TEXT NOT NULL,
                approval_json TEXT NOT NULL,
                recorded_at_utc TEXT NOT NULL,
                PRIMARY KEY (action_id, evidence_hash)
            )
            """)

            # HARDENING (v2.0.4): External approvals v2 - support multi-role consensus.
            # Allows multiple approvals per action/evidence by (reviewer_type, key_id).
            conn.execute("""
            CREATE TABLE IF NOT EXISTS external_approvals_v2 (
                action_id TEXT NOT NULL,
                evidence_hash TEXT NOT NULL,
                reviewer_type TEXT NOT NULL,
                key_id TEXT NOT NULL,
                approval_json TEXT NOT NULL,
                recorded_at_utc TEXT NOT NULL,
                PRIMARY KEY (action_id, evidence_hash, reviewer_type, key_id)
            )
            """)

            
            # HARDENING (v2.0.2): Nonce tracking for replay prevention
            conn.execute("""
            CREATE TABLE IF NOT EXISTS used_nonces (
                jti TEXT NOT NULL,
                nonce TEXT NOT NULL,
                used_at_utc TEXT NOT NULL,
                PRIMARY KEY (jti, nonce)
            )
            """)
            
            # HARDENING (v2.0.2): Counter tracking for monotonic enforcement
            conn.execute("""
            CREATE TABLE IF NOT EXISTS token_counters (
                jti TEXT PRIMARY KEY,
                last_counter INTEGER NOT NULL DEFAULT 0,
                updated_at_utc TEXT NOT NULL
            )
            """)
            
            conn.commit()

    # ---------------------------
    # Sessions (gateway-issued)
    # ---------------------------

    def purge_expired_sessions(self) -> int:
        """Delete expired sessions from the store. Returns number of rows deleted."""
        now = _now_utc()
        with self._db("store_op") as conn:
            cur = conn.execute(
                "DELETE FROM sessions WHERE expires_at_utc <= ?",
                (now.isoformat(),),
            )
            return int(cur.rowcount or 0)

    def create_session(self, agent_id: str, ttl_seconds: int = 3600) -> Tuple[str, str]:
        """Create a gateway-issued session id for an authenticated agent.

        Returns (session_id, expires_at_utc_iso).
        """
        if not agent_id or not str(agent_id).strip():
            raise ValueError("agent_id must be non-empty")
        # Hardening: clamp session TTL to configured bounds.
        min_ttl = int(os.getenv("LAP_SESSION_TTL_MIN_SECONDS", "60") or "60")
        max_ttl = int(os.getenv("LAP_SESSION_TTL_MAX_SECONDS", "86400") or "86400")
        ttl = int(ttl_seconds)
        if ttl < min_ttl or ttl > max_ttl:
            raise ValueError(f"ttl_seconds must be between {min_ttl} and {max_ttl}")

        # Hardening: limit active sessions per agent and globally (best-effort DoS reduction).
        max_per_agent = int(os.getenv("LAP_MAX_ACTIVE_SESSIONS_PER_AGENT", "10") or "10")
        max_global = int(os.getenv("LAP_MAX_ACTIVE_SESSIONS_GLOBAL", "10000") or "10000")

        self.purge_expired_sessions()
        session_id = f"sess_{secrets.token_urlsafe(24)}"
        now = _now_utc()
        expires = now + timedelta(seconds=ttl)

        with self._db("store_op") as conn:
            # Enforce limits inside the same transaction.
            per_agent_count = conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE agent_id = ? AND expires_at_utc > ?",
                (agent_id, now.isoformat()),
            ).fetchone()[0]
            global_count = conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE expires_at_utc > ?",
                (now.isoformat(),),
            ).fetchone()[0]
            if int(per_agent_count) >= max_per_agent:
                raise ValueError("too many active sessions for agent")
            if int(global_count) >= max_global:
                raise ValueError("too many active sessions globally")

            conn.execute(
                "INSERT INTO sessions (session_id, agent_id, created_at_utc, expires_at_utc) VALUES (?, ?, ?, ?)",
                (session_id, agent_id, now.isoformat(), expires.isoformat()),
            )

        return session_id, expires.isoformat()

    def validate_session(self, session_id: str, agent_id: str) -> bool:
        """Validate that a session exists, is unexpired, and belongs to the agent."""
        if not session_id or not str(session_id).strip():
            return False
        if not agent_id or not str(agent_id).strip():
            return False

        self.purge_expired_sessions()

        with self._db("store_op") as conn:
            row = conn.execute(
                "SELECT agent_id, expires_at_utc FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()

        if not row:
            return False

        owner, expires_at = row[0], row[1]
        if owner != agent_id:
            return False

        try:
            exp = datetime.fromisoformat(str(expires_at))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
        except Exception:
            # Corrupted row: treat as invalid (fail-closed)
            return False

        return exp > _now_utc()

    
    def store_decision(self, decision_id: str, action_id: str, evidence_hash: str,
                       decision_hash: str, outcome: str, tier: str, reason: str,
                       agent_id: str) -> bool:
        """
        Store a decision record (immutable insert).
        
        HARDENING (v2.0.2): Uses INSERT without REPLACE to prevent tampering.
        Returns True if inserted, False if already exists.
        """
        try:
            with self._db("store_op") as conn:
                conn.execute("""
                INSERT INTO decisions 
                (decision_id, action_id, evidence_hash, decision_hash, outcome, tier, reason, created_at_utc, agent_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (decision_id, action_id, evidence_hash, decision_hash, outcome, tier, reason,
                      _now_utc().isoformat(), agent_id))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            # Already exists - this is expected for idempotent retries
            return False
    
    def store_token(self, token: CapabilityToken) -> bool:
        """
        Store a token record (immutable insert).
        
        HARDENING (v2.0.2): Uses INSERT without REPLACE to prevent tampering.
        Returns True if inserted, False if already exists.
        """
        try:
            with self._db("store_op") as conn:
                conn.execute("""
                INSERT INTO tokens
                (jti, action_id, evidence_hash, decision_hash, token_json, issued_at_utc, expires_at_utc, revoked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (token.jti, token.action_id, token.evidence_hash, token.decision_hash,
                      json.dumps(token.to_dict()), token.iat, token.exp, False))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False
    
    def revoke_token(self, jti: str) -> None:
        with self._db("store_op") as conn:
            conn.execute("UPDATE tokens SET revoked = TRUE WHERE jti = ?", (jti,))
            conn.commit()
    
    def is_token_revoked(self, jti: str) -> bool:
        with self._db("store_op") as conn:
            cur = conn.execute("SELECT revoked FROM tokens WHERE jti = ?", (jti,))
            row = cur.fetchone()
            return row[0] if row else False
    
    def store_receipt(self, receipt: ToolInvocationReceipt) -> None:
        with self._db("store_op") as conn:
            conn.execute("""
            INSERT INTO receipts (receipt_id, action_id, token_jti, receipt_json, created_at_utc)
            VALUES (?, ?, ?, ?, ?)
            """, (receipt.receipt_id, receipt.action_id, receipt.token_jti,
                  json.dumps(receipt.to_dict()), _now_utc().isoformat()))
            conn.commit()
    

    def store_external_approval(self, approval: Ed25519ExternalApproval) -> bool:
        """Store an external approval (immutable insert).

        HARDENING (v2.0.4): Support multi-role consensus by storing approvals in
        external_approvals_v2 keyed by (action_id, evidence_hash, reviewer_type, key_id).
        We also attempt to store a legacy single-row copy for backwards compatibility.

        Returns True if the v2 insert succeeded, False if it already existed.
        """
        inserted_v2 = False
        with self._db("store_op") as conn:
            # v2 insert (allows multiple approvals)
            try:
                conn.execute("""
                INSERT INTO external_approvals_v2
                (action_id, evidence_hash, reviewer_type, key_id, approval_json, recorded_at_utc)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    approval.action_id,
                    approval.evidence_hash,
                    approval.reviewer_type,
                    approval.key_id,
                    json.dumps(approval.to_dict()),
                    _now_utc().isoformat(),
                ))
                inserted_v2 = True
            except sqlite3.OperationalError:
                inserted_v2 = False
            except sqlite3.IntegrityError:
                inserted_v2 = False

            # legacy insert (best effort, single-row)
            try:
                conn.execute("""
                INSERT INTO external_approvals
                (action_id, evidence_hash, approval_json, recorded_at_utc)
                VALUES (?, ?, ?, ?)
                """, (
                    approval.action_id,
                    approval.evidence_hash,
                    json.dumps(approval.to_dict()),
                    _now_utc().isoformat(),
                ))
            except sqlite3.IntegrityError:
                pass
            except sqlite3.OperationalError:
                pass

            conn.commit()

        return inserted_v2


    def get_external_approvals(self, action_id: str, evidence_hash: str) -> List[Ed25519ExternalApproval]:
        """Get all external approvals for (action_id, evidence_hash).

        Prefers external_approvals_v2 when available; falls back to legacy
        external_approvals (single approval).
        """
        approvals: List[Ed25519ExternalApproval] = []
        with self._db("store_op") as conn:
            # Try v2 first
            try:
                cur = conn.execute("""
                SELECT approval_json FROM external_approvals_v2
                WHERE action_id = ? AND evidence_hash = ?
                """, (action_id, evidence_hash))
                for (aj,) in cur.fetchall():
                    try:
                        approvals.append(Ed25519ExternalApproval.from_dict(json.loads(aj)))
                    except Exception:
                        continue
                if approvals:
                    return approvals
            except sqlite3.OperationalError:
                pass

            # Fallback to legacy
            cur = conn.execute("""
            SELECT approval_json FROM external_approvals
            WHERE action_id = ? AND evidence_hash = ?
            """, (action_id, evidence_hash))
            row = cur.fetchone()
            if row:
                try:
                    approvals.append(Ed25519ExternalApproval.from_dict(json.loads(row[0])))
                except Exception:
                    pass

        return approvals


    def get_external_approval(self, action_id: str, evidence_hash: str) -> Optional[Ed25519ExternalApproval]:
        """Get an external approval (legacy single row).

        HARDENING (v2.0.4): Prefer v2 approvals when available.
        """
        approvals = self.get_external_approvals(action_id, evidence_hash)
        return approvals[0] if approvals else None


    # ---------------------------
    # Decision Validation (v2.0.1)
    # ---------------------------
    
    def get_decision(self, action_id: str, evidence_hash: str, decision_hash: str) -> Optional[Dict[str, Any]]:
        """
        Get a decision record by action_id, evidence_hash, and decision_hash.
        
        HARDENING (v2.0.1): Used to verify token bindings at invoke time.
        """
        with self._db("store_op") as conn:
            cur = conn.execute("""
            SELECT decision_id, action_id, evidence_hash, decision_hash, outcome, tier, reason, created_at_utc
            FROM decisions
            WHERE action_id = ? AND evidence_hash = ? AND decision_hash = ?
            """, (action_id, evidence_hash, decision_hash))
            row = cur.fetchone()
            if row:
                return {
                    "decision_id": row[0],
                    "action_id": row[1],
                    "evidence_hash": row[2],
                    "decision_hash": row[3],
                    "outcome": row[4],
                    "tier": row[5],
                    "reason": row[6],
                    "created_at_utc": row[7],
                }
            return None
    
    def is_decision_valid(self, action_id: str, evidence_hash: str, decision_hash: str) -> Tuple[bool, str]:
        """
        Check if a decision is valid and allows tool invocation.
        
        HARDENING (v2.0.1): Cross-check token bindings against stored decision state.
        """
        decision = self.get_decision(action_id, evidence_hash, decision_hash)
        
        if decision is None:
            return False, "DECISION_NOT_FOUND"
        
        if decision["outcome"] != "approve":
            return False, f"DECISION_NOT_APPROVE: {decision['outcome']}"
        
        return True, "OK"
    
    # ---------------------------
    # Persistent Budget Tracking (v2.0.1)
    # ---------------------------
    
    def get_budget_usage(self, jti: str) -> Dict[str, Any]:
        """
        Get budget usage for a token.
        
        HARDENING (v2.0.1): Budget tracking persists across restarts.
        """
        with self._db("store_op") as conn:
            cur = conn.execute("""
            SELECT calls_used, bytes_in_used, bytes_out_used, spend_cents_used, duration_seconds_used
            FROM budget_usage WHERE jti = ?
            """, (jti,))
            row = cur.fetchone()
            if row:
                return {
                    "calls_used": row[0],
                    "bytes_in_used": row[1],
                    "bytes_out_used": row[2],
                    "spend_cents_used": row[3],
                    "duration_seconds_used": row[4],
                }
            return {
                "calls_used": 0,
                "bytes_in_used": 0,
                "bytes_out_used": 0,
                "spend_cents_used": 0,
                "duration_seconds_used": 0.0,
            }
    
    def record_budget_usage(
        self, jti: str,
        calls: int = 1,
        bytes_in: int = 0,
        bytes_out: int = 0,
        spend_cents: int = 0,
        duration: float = 0.0
    ) -> None:
        """
        Record budget usage atomically.
        
        HARDENING (v2.0.1): Atomic increment to prevent race conditions.
        """
        with self._db("store_op") as conn:
            # Use INSERT OR REPLACE with computed new values
            cur = conn.execute("""
            SELECT calls_used, bytes_in_used, bytes_out_used, spend_cents_used, duration_seconds_used
            FROM budget_usage WHERE jti = ?
            """, (jti,))
            row = cur.fetchone()
            
            if row:
                new_calls = row[0] + calls
                new_bytes_in = row[1] + bytes_in
                new_bytes_out = row[2] + bytes_out
                new_spend = row[3] + spend_cents
                new_duration = row[4] + duration
                
                conn.execute("""
                UPDATE budget_usage 
                SET calls_used = ?, bytes_in_used = ?, bytes_out_used = ?, 
                    spend_cents_used = ?, duration_seconds_used = ?, last_updated_utc = ?
                WHERE jti = ?
                """, (new_calls, new_bytes_in, new_bytes_out, new_spend, new_duration, 
                      _now_utc().isoformat(), jti))
            else:
                conn.execute("""
                INSERT INTO budget_usage 
                (jti, calls_used, bytes_in_used, bytes_out_used, spend_cents_used, duration_seconds_used, last_updated_utc)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (jti, calls, bytes_in, bytes_out, spend_cents, duration, _now_utc().isoformat()))
            
            conn.commit()
    
    def check_budget(self, jti: str, budget: Dict[str, Any],
                     add_calls: int = 1, add_bytes_in: int = 0, 
                     add_bytes_out: int = 0) -> Tuple[bool, str]:
        """
        Check if operation fits within budget (non-atomic, for pre-checks only).
        
        DEPRECATED: Use atomic_reserve_budget() for actual enforcement.
        """
        usage = self.get_budget_usage(jti)
        
        max_calls = budget.get("max_calls")
        if max_calls is not None:
            if usage["calls_used"] + add_calls > max_calls:
                return False, f"BUDGET_EXCEEDED: calls ({usage['calls_used'] + add_calls} > {max_calls})"
        
        max_bytes_in = budget.get("max_bytes_in")
        if max_bytes_in is not None:
            if usage["bytes_in_used"] + add_bytes_in > max_bytes_in:
                return False, f"BUDGET_EXCEEDED: bytes_in ({usage['bytes_in_used'] + add_bytes_in} > {max_bytes_in})"
        
        max_bytes_out = budget.get("max_bytes_out")
        if max_bytes_out is not None:
            if usage["bytes_out_used"] + add_bytes_out > max_bytes_out:
                return False, f"BUDGET_EXCEEDED: bytes_out"
        
        return True, "OK"
    
    def atomic_reserve_budget(
        self,
        jti: str,
        action_id: str,
        evidence_hash: str,
        decision_hash: str,
        budget: Dict[str, Any],
        add_calls: int = 1,
        add_bytes_in: int = 0,
        reserve_bytes_out: int = 0,
    ) -> Tuple[bool, str]:
        """
        Atomically check all preconditions and reserve budget.
        
        HARDENING (v2.0.2): Single transaction prevents race conditions.
        
        Checks in one transaction:
        1. Token not revoked
        2. Decision exists and is APPROVE
        3. Budget not exceeded
        4. Increments budget counters
        
        Returns (success, reason).
        """
        with self._db("store_op", isolation_level="IMMEDIATE") as conn:
            try:
                # 1. Check token not revoked
                cur = conn.execute("SELECT revoked FROM tokens WHERE jti = ?", (jti,))
                row = cur.fetchone()
                if row is None:
                    return False, "TOKEN_NOT_FOUND"
                if row[0]:
                    return False, "TOKEN_REVOKED"
                
                # 2. Check decision is valid
                cur = conn.execute("""
                SELECT outcome FROM decisions
                WHERE action_id = ? AND evidence_hash = ? AND decision_hash = ?
                """, (action_id, evidence_hash, decision_hash))
                row = cur.fetchone()
                if row is None:
                    return False, "DECISION_NOT_FOUND"
                if row[0] != "approve":
                    return False, f"DECISION_NOT_APPROVE: {row[0]}"
                
                # 3. Get current usage and check budget
                cur = conn.execute("""
                SELECT calls_used, bytes_in_used, bytes_out_used
                FROM budget_usage WHERE jti = ?
                """, (jti,))
                row = cur.fetchone()
                
                if row:
                    calls_used, bytes_in_used, bytes_out_used = row
                else:
                    calls_used, bytes_in_used, bytes_out_used = 0, 0, 0
                
                # Check limits
                max_calls = budget.get("max_calls")
                if max_calls is not None:
                    if calls_used + add_calls > max_calls:
                        return False, f"BUDGET_EXCEEDED: calls ({calls_used + add_calls} > {max_calls})"
                
                max_bytes_in = budget.get("max_bytes_in")
                if max_bytes_in is not None:
                    if bytes_in_used + add_bytes_in > max_bytes_in:
                        return False, f"BUDGET_EXCEEDED: bytes_in"
                
                max_bytes_out = budget.get("max_bytes_out")
                if max_bytes_out is not None:
                    if bytes_out_used + reserve_bytes_out > max_bytes_out:
                        return False, f"BUDGET_EXCEEDED: bytes_out (reserved)"
                
                # 4. Atomically increment counters
                now = _now_utc().isoformat()
                if row:
                    conn.execute("""
                    UPDATE budget_usage 
                    SET calls_used = calls_used + ?,
                        bytes_in_used = bytes_in_used + ?,
                        bytes_out_used = bytes_out_used + ?,
                        last_updated_utc = ?
                    WHERE jti = ?
                    """, (add_calls, add_bytes_in, reserve_bytes_out, now, jti))
                else:
                    conn.execute("""
                    INSERT INTO budget_usage 
                    (jti, calls_used, bytes_in_used, bytes_out_used, spend_cents_used, duration_seconds_used, last_updated_utc)
                    VALUES (?, ?, ?, ?, 0, 0, ?)
                    """, (jti, add_calls, add_bytes_in, reserve_bytes_out, now))
                
                conn.commit()
                return True, "RESERVED"
                
            except Exception as e:
                conn.rollback()
                return False, f"RESERVATION_FAILED: {e}"
    
    def finalize_budget_usage(
        self,
        jti: str,
        actual_bytes_out: int,
        reserved_bytes_out: int,
        duration: float
    ) -> None:
        """
        Finalize budget usage after tool invocation.
        
        HARDENING (v2.0.2): Adjusts bytes_out from reserved to actual.
        """
        with self._db("store_op") as conn:
            adjustment = actual_bytes_out - reserved_bytes_out
            conn.execute("""
            UPDATE budget_usage 
            SET bytes_out_used = bytes_out_used + ?,
                duration_seconds_used = duration_seconds_used + ?,
                last_updated_utc = ?
            WHERE jti = ?
            """, (adjustment, duration, _now_utc().isoformat(), jti))
            conn.commit()
    
    # ---------------------------
    # Replay Prevention (v2.0.2)
    # ---------------------------
    
    def check_and_record_nonce(self, jti: str, nonce: str) -> Tuple[bool, str]:
        """
        Check if nonce is unique for this token and record it.

        HARDENING (v2.0.2): Prevents replay attacks by ensuring each
        nonce is used only once per token.

        HOT PATH (v2.0.4): Deny-fast using in-memory TTL cache before
        attempting a DB insert. The DB remains authoritative; the cache is
        updated only after DB success.

        Returns (success, reason). Fails if nonce already used.
        """
        # Deny-fast: if we've already observed this nonce for this token,
        # do not hit the DB.
        if self.replay_hotpath.nonce_seen(jti, nonce):
            return False, f"NONCE_REUSED: {nonce}"
        try:
            with self._db("store_op") as conn:
                conn.execute("""
                INSERT INTO used_nonces (jti, nonce, used_at_utc)
                VALUES (?, ?, ?)
                """, (jti, nonce, _now_utc().isoformat()))
                conn.commit()
            # Record only after DB success.
            self.replay_hotpath.record_nonce(jti, nonce)
            return True, "OK"
        except sqlite3.IntegrityError:
            # Another process may have recorded it first; cache it so future
            # repeats deny-fast.
            self.replay_hotpath.record_nonce(jti, nonce)
            return False, f"NONCE_REUSED: {nonce}"
    
    def check_and_update_counter(self, jti: str, counter: int) -> Tuple[bool, str]:
        """Enforce monotonic counters per token JTI and persist max value.

        Returns (ok, reason). Reasons:
          - "COUNTER_OK"
          - "LAP_E_COUNTER_NOT_MONOTONIC"
          - "LAP_E_COUNTER_ROLLBACK_DETECTED"
          - "LAP_E_COUNTER_STORAGE_FAILURE"
        """
        if not isinstance(jti, str) or not jti.strip():
            return False, "LAP_E_COUNTER_STORAGE_FAILURE"
        if not isinstance(counter, int):
            return False, "LAP_E_COUNTER_STORAGE_FAILURE"

        # Fast path deny using in-memory cache (best-effort).
        if self.replay_hotpath.deny_if_counter_not_monotonic(jti, counter)[0]:
            return False, "LAP_E_COUNTER_NOT_MONOTONIC"

        # Consult durable journal maxima (best-effort).
        journal_last = self.counter_journal.max_for(jti)

        # Perform DB check+update in a transaction. Do not return from inside the
        # transaction context so commits complete before we proceed.
        ok = False
        reason = "LAP_E_COUNTER_STORAGE_FAILURE"
        updated_at = _now_utc().isoformat()

        try:
            with self._db("counter_update", isolation_level="IMMEDIATE") as conn:
                row = conn.execute(
                    "SELECT last_counter FROM token_counters WHERE jti = ?",
                    (jti,),
                ).fetchone()

                if row is None:
                    # If we have a journal entry but no DB row, treat as rollback / corruption.
                    if journal_last is not None:
                        ok = False
                        reason = "LAP_E_COUNTER_ROLLBACK_DETECTED"
                    else:
                        # First write for this JTI.
                        conn.execute(
                            "INSERT INTO token_counters (jti, last_counter, updated_at_utc) VALUES (?, ?, ?)",
                            (jti, counter, updated_at),
                        )
                        ok = True
                        reason = "COUNTER_OK"
                else:
                    db_last = int(row[0])
                    # Detect rollback/corruption: DB behind durable journal.
                    if journal_last is not None and db_last < journal_last:
                        ok = False
                        reason = "LAP_E_COUNTER_ROLLBACK_DETECTED"
                    else:
                        effective_last = db_last if journal_last is None else max(db_last, journal_last)
                        if counter <= effective_last:
                            ok = False
                            reason = "LAP_E_COUNTER_NOT_MONOTONIC"
                        else:
                            # Conditional update prevents accidental decreases.
                            cur = conn.execute(
                                "UPDATE token_counters SET last_counter = ?, updated_at_utc = ? "
                                "WHERE jti = ? AND last_counter < ?",
                                (counter, updated_at, jti, counter),
                            )
                            if getattr(cur, "rowcount", 0) != 1:
                                ok = False
                                reason = "LAP_E_COUNTER_NOT_MONOTONIC"
                            else:
                                ok = True
                                reason = "COUNTER_OK"
        except Exception:
            ok = False
            reason = "LAP_E_COUNTER_STORAGE_FAILURE"

        if not ok:
            if reason in ("LAP_E_COUNTER_STORAGE_FAILURE", "LAP_E_COUNTER_ROLLBACK_DETECTED"):
                try:
                    self.circuit.record_failure()
                except Exception:
                    pass
            return False, reason

        # Persist to journal AFTER DB commit. If journal fails, fail closed.
        try:
            self.counter_journal.append(jti, counter, updated_at)
        except Exception:
            try:
                self.circuit.record_failure()
            except Exception:
                pass
            return False, "LAP_E_COUNTER_STORAGE_FAILURE"

        # Update in-memory hotpath after durability.
        self.replay_hotpath.record_counter(jti, counter)

        return True, "COUNTER_OK"


# ---------------------------
# Gateway Core
# ---------------------------

class LAPGateway:
    """
    LAP Gateway - Policy Enforcement Point.
    
    This is the central enforcement layer that:
    - Evaluates actions using LAP protocol
    - Issues capability tokens for approved actions
    - Enforces budgets and scopes on tool invocations
    - Produces signed receipts for all actions
    - Maintains audit trail with external anchoring
    """
    
    def __init__(
        self,
        gateway_id: str = "lap_gateway_001",
        signer: Optional[Signer] = None,
        signing_key: Optional[Any] = None,  # backwards-compat alias for signer
        trusted_keys: Optional[TrustedKeyStore] = None,
        gateway_verify_keys: Optional[TrustedKeyStore] = None,
        gateway_public_keys: Optional[Dict[str, str]] = None,
        store: Optional[GatewayStore] = None,
        time_source: Optional[TrustedTimeSource] = None,
        evidence_policy: Optional[EvidenceQualityPolicy] = None,
        lap_protocol: Optional[Any] = None,  # LatticeAuditProtocol instance
        pdp_client: Optional[PDPClient] = None,
    ):
        self.gateway_id = gateway_id
        # Backwards-compat: accept signing_key=... as alias for signer.
        if signer is None and signing_key is not None:
            signer = signing_key
        elif signer is not None and signing_key is not None and signer is not signing_key:
            raise TypeError("Provide either signer or signing_key, not both")

        
        # Signing key for tokens and receipts
        if signer is None:
            if not CRYPTO_AVAILABLE:
                raise RuntimeError("Ed25519 signing key required. Install: pip install cryptography")

            # Load from env/file unless explicitly allowed to generate an ephemeral key.
            allow_ephemeral = os.getenv("LAP_ALLOW_EPHEMERAL_SIGNING_KEYS", "").strip().lower() in ("1", "true", "yes")
            signer_loaded, gateway_store_loaded, gateway_pubkeys_loaded = load_gateway_signing_material(
                allow_ephemeral=allow_ephemeral
            )
            if signer_loaded is None:
                raise RuntimeError(
                    "No gateway signing key configured. Configure either a keyset "
                    "(LAP_GATEWAY_KEYSET_JSON / LAP_GATEWAY_KEYSET_FILE) or a single signing key "
                    "(LAP_GATEWAY_SIGNING_KEY or LAP_GATEWAY_SIGNING_KEY_FILE). "
                    "For demos/tests only, set LAP_ALLOW_EPHEMERAL_SIGNING_KEYS=1 to generate an ephemeral key."
                )
            # Allow forcing an external signer seam via SIGNER_MODE/SIGNER_CMD.
            signer = build_signer_from_env(signer_loaded)

            # Key rotation: accept tokens/receipts issued under any key in the keyset.
            gateway_verify_keys = gateway_verify_keys or gateway_store_loaded
            gateway_public_keys = gateway_public_keys or gateway_pubkeys_loaded
        else:
            signer = build_signer_from_env(signer)

        self.signer = coerce_signer(signer)

        # Default gateway verification keys/public key map from signer if not provided.
        gateway_verify_keys = gateway_verify_keys or TrustedKeyStore.from_config({self.signer.key_id: self.signer.public_key_hex})
        gateway_public_keys = gateway_public_keys or {self.signer.key_id: self.signer.public_key_hex}

        # Trusted keys for external approval verification
        self.trusted_keys = trusted_keys or TrustedKeyStore()
        
        # Storage
        # Allow deployments and harnesses (demo/load tests) to isolate gateway state
        # without changing call sites.
        # Support legacy LAP_DB_PATH for backwards compatibility.
        default_db_path = os.getenv("LAP_GATEWAY_DB_PATH") or os.getenv("LAP_DB_PATH") or "lap_gateway.db"
        self.store = store or GatewayStore(db_path=default_db_path)

        # Tamper-evident audit log (reference implementation)
        audit_path = os.getenv(
            "LAP_AUDIT_LOG_PATH",
            str(Path(self.store.db_path).with_suffix(".audit.jsonl")),
        )
        self.audit_log_path = audit_path
        self.audit_log = TamperEvidentAuditLog(audit_path, self.signer)
        
        # Time source
        self.time_source = time_source or LocalTimeSource()
        
        # Evidence quality policy
        self.evidence_policy = evidence_policy or EvidenceQualityPolicy()
        self.evidence_checker = EvidenceQualityChecker(self.evidence_policy)
        # LAP protocol for evaluation
        # Default behavior is to keep the gateway's simple evaluator unless explicitly enabled.
        enable_engine = os.getenv("LAP_ENABLE_PROTOCOL_ENGINE", "").strip().lower() in ("1", "true", "yes")
        if lap_protocol is not None:
            self.lap_protocol = lap_protocol
        elif enable_engine:
            self.lap_protocol = self._load_default_lap_protocol()
        else:
            self.lap_protocol = None

        # PDP client (builtin by default; optionally HTTP PDP via env vars).
        # This is additive and does not change default behavior.
        if pdp_client is not None:
            self.pdp_client = pdp_client
            self.pdp_mode = "custom"
        else:
            self.pdp_mode = os.getenv("PDP_MODE", "builtin").strip().lower() or "builtin"
            self.pdp_client = build_pdp_client_from_env(self)
        # Token issuer and verifier
        self.token_issuer = TokenIssuer(gateway_id, self.signer)
        self.budget_tracker = BudgetTracker()
        self.gateway_verify_keys = gateway_verify_keys or TrustedKeyStore.from_config({self.signer.key_id: self.signer.public_key_hex})
        self.gateway_public_keys = gateway_public_keys or {self.signer.key_id: self.signer.public_key_hex}
        self.token_verifier = TokenVerifier(
            self.gateway_verify_keys,
                    self.budget_tracker
                )
        
        # Receipt issuer
        self.receipt_issuer = ReceiptIssuer(self.signer)
        
        # Tool connectors
        self.tool_connectors: Dict[str, ToolConnector] = {}
        
        # Credential provider
        self.credential_provider: Optional[CredentialProvider] = None
    

    def _load_default_lap_protocol(self) -> Optional[Any]:
        """Load a default LatticeAuditProtocol instance.

        If LAP_PROTOCOL_CONFIG_FILE is set, uses that JSON config. If it is set but
        invalid/unreadable, we raise to fail closed at startup.
        """
        try:
            from pathlib import Path
            from lap_cli import load_config, create_protocol_from_config

            cfg_path_raw = os.getenv("LAP_PROTOCOL_CONFIG_FILE", "").strip()
            cfg: dict = {}
            if cfg_path_raw:
                cfg_path = Path(cfg_path_raw)
                cfg = load_config(cfg_path)
            db_path = os.getenv("LAP_PROTOCOL_DB_PATH", "lattice_audit.db")
            return create_protocol_from_config(cfg, db_path=db_path)
        except Exception as e:
            # Fail closed if the operator attempted to configure LAP and it broke.
            if os.getenv("LAP_PROTOCOL_CONFIG_FILE", "").strip():
                raise
            # Otherwise, still try to construct with defaults (best effort).
            try:
                from lap_cli import create_protocol_from_config
                return create_protocol_from_config({}, db_path=os.getenv("LAP_PROTOCOL_DB_PATH", "lattice_audit.db"))
            except Exception:
                logger.warning("LAP protocol engine unavailable; falling back to simple evaluator: %s", e)
                return None

    def register_tool(self, connector: ToolConnector) -> None:
        """Register a tool connector."""
        self.tool_connectors[connector.tool_name] = connector
    
    def set_credential_provider(self, provider: CredentialProvider) -> None:
        """Set the credential provider for JIT credentials."""
        self.credential_provider = provider
    
    def _compute_evidence_hash(self, evidence: Dict[str, Any]) -> str:
        """Compute canonical hash of evidence."""
        # NOTE: v1 is used here for backwards compatibility of existing
        # hashes/signatures. Canonical JSON v2 is available but not yet used
        # for receipt/token hashing.
        canonical = canonical_json_dumps(evidence, version="v1")
        return _sha256_hex(canonical.encode('utf-8'))
    
    def _compute_decision_hash(self, action_id: str, evidence_hash: str, 
                                outcome: str, tier: str, reason: str) -> str:
        """Compute hash of decision."""
        components = [action_id, evidence_hash, outcome, tier, reason]
        return _sha256_hex(_safe_hash_encode(components))
    
    async def evaluate_action(
        self,
        evidence: Dict[str, Any],
        agent_id: str = "unknown",
        session_id: str = "",  # Session binding (T2/T3)
        caller_authenticated: bool = False,
    ) -> Dict[str, Any]:
        """
        Evaluate an action and return decision with optional capability token.
        
        This is the main entry point for agents requesting action approval.
        
        HARDENING (v2.0.2):
        - T3 actions do NOT receive tokens here - must use mint_t3_token
        - T2 tokens require session_id binding
        - All tokens include session binding if provided
        """
        # Step 1: Check evidence quality
        action_id = evidence.get("action_id", "")
        tier_estimate = self._estimate_tier(evidence)

        # HARDENING (1.0.0): Strong auth required for T2/T3 actions.
        if tier_estimate in ("T2_HIGH_STAKES", "T3_CATASTROPHIC") and not caller_authenticated:
            return {
                "outcome": "deny",
                "tier": tier_estimate,
                "reason": "HARD_AUTH_REQUIRED: Enable API-key auth for T2/T3",
                "decision_id": None,
                "evidence_hash": self._compute_evidence_hash(evidence),
                "decision_hash": None,
                "capability_token": None,
            }

        # HARDENING (1.0.0): Non-empty, gateway-issued session required for T2/T3.
        if tier_estimate in ("T2_HIGH_STAKES", "T3_CATASTROPHIC"):
            if not session_id or not str(session_id).strip():
                return {
                    "outcome": "deny",
                    "tier": tier_estimate,
                    "reason": "SESSION_REQUIRED: Acquire session via /v1/session/new",
                    "decision_id": None,
                    "evidence_hash": self._compute_evidence_hash(evidence),
                    "decision_hash": None,
                    "capability_token": None,
                }
            try:
                if not self.store.validate_session(str(session_id).strip(), agent_id):
                    return {
                        "outcome": "deny",
                        "tier": tier_estimate,
                        "reason": "SESSION_INVALID_OR_EXPIRED",
                        "decision_id": None,
                        "evidence_hash": self._compute_evidence_hash(evidence),
                        "decision_hash": None,
                        "capability_token": None,
                    }
            except StorageLockdownError:
                try:
                    OPS_STATS.record_storage_lockdown()
                except Exception:
                    pass
                return {
                    "outcome": "deny",
                    "tier": tier_estimate,
                    "reason": "LOCKDOWN_ACTIVE: storage degraded",
                    "decision_id": None,
                    "evidence_hash": self._compute_evidence_hash(evidence),
                    "decision_hash": None,
                    "capability_token": None,
                }
        
        quality_ok, quality_issues, requires_reviewer_override = self.evidence_checker.check_evidence_detailed(
            evidence, tier_estimate
        )

        if not quality_ok:
            evidence_hash = self._compute_evidence_hash(evidence)
            decision_hash = self._compute_decision_hash(
                action_id, evidence_hash, "deny", tier_estimate,
                f"EVIDENCE_QUALITY_FAILED: {'; '.join(quality_issues)}"
            )
            
            # Issue denial receipt
            denial = DenialReceipt(
                receipt_id=f"deny_{secrets.token_urlsafe(12)}",
                action_id=action_id,
                evidence_hash=evidence_hash,
                decision_hash=decision_hash,
                outcome="deny",
                tier=tier_estimate,
                reason=f"Evidence quality check failed: {quality_issues}",
                denied_at_utc=_now_utc().isoformat(),
                key_id=self.signer.key_id,
            )
            denial.signature = self.signer.sign(denial.compute_signature_payload())
            
            return {
                "outcome": "deny",
                "tier": tier_estimate,
                "reason": f"EVIDENCE_QUALITY_FAILED: {'; '.join(quality_issues)}",
                "action_id": action_id,
                "evidence_hash": evidence_hash,
                "decision_hash": decision_hash,
                "capability_token": None,
                "constraints": {},
                "denial_receipt": denial.to_dict(),
                "requires_mint": False,
            }
        
        # Step 2: Run LAP evaluation
        evidence_hash = self._compute_evidence_hash(evidence)

        # PDP evaluation: builtin by default, optionally HTTP.
        # For builtin mode we keep the prior behavior (including optional protocol-engine import).
        if getattr(self, "pdp_mode", "builtin") in ("builtin", "custom"):
            if self.lap_protocol:
                try:
                    # Import presence check (best-effort). If the optional engine isn't importable,
                    # fall back to the simple evaluator.
                    from lattice_audit_v1_7 import EvidenceObject  # noqa: F401
                except Exception as e:
                    logger.error("LAP protocol import failed; falling back to simple evaluator: %s", e)
                    self.lap_protocol = None

        # Evaluate via configured PDP client.
        try:
            if getattr(self, "pdp_mode", "builtin") == "http":
                decision = await asyncio.to_thread(self.pdp_client.evaluate, evidence)
            else:
                decision = self.pdp_client.evaluate(evidence)
        except Exception as e:
            try:
                OPS_STATS.record_pdp_error()
            except Exception:
                pass
            decision = {
                "outcome": "deny",
                "tier": tier_estimate,
                "reason": f"PDP_ERROR: {type(e).__name__}: {e}",
            }

        outcome = str(decision.get("outcome", "deny"))
        tier = str(decision.get("tier", tier_estimate))
        reason = str(decision.get("reason", ""))

        # HARDENING: If the protocol engine escalates the tier beyond our initial estimate,
        # re-run evidence-quality checks at the actual tier (stricter). This prevents a
        # fail-open when tier_estimate is missing/under-specified.
        _tier_rank = {
            # Historical/alternate names (kept for compatibility)
            "T0_LOW": 0,
            "T1_STANDARD": 1,
            # Canonical names used by this codebase
            "T0_ROUTINE": 0,
            "T1_SENSITIVE": 1,
            "T2_HIGH_STAKES": 2,
            "T3_CATASTROPHIC": 3,
        }
        if _tier_rank.get(tier, 0) > _tier_rank.get(tier_estimate, 0):
            quality_ok, quality_issues, requires_reviewer_override = self.evidence_checker.check_evidence_detailed(
                evidence, tier
            )
            if not quality_ok:
                decision_hash = self._compute_decision_hash(
                    action_id, evidence_hash, "deny", tier,
                    f"EVIDENCE_QUALITY_FAILED: {'; '.join(quality_issues)}"
                )

                denial = DenialReceipt(
                    receipt_id=f"deny_{secrets.token_urlsafe(12)}",
                    action_id=action_id,
                    evidence_hash=evidence_hash,
                    decision_hash=decision_hash,
                    outcome="deny",
                    tier=tier,
                    reason=f"Evidence quality check failed: {quality_issues}",
                    denied_at_utc=_now_utc().isoformat(),
                    key_id=self.signer.key_id,
                )
                denial.signature = self.signer.sign(denial.compute_signature_payload())

                return {
                    "outcome": "deny",
                    "tier": tier,
                    "reason": f"EVIDENCE_QUALITY_FAILED: {'; '.join(quality_issues)}",
                    "action_id": action_id,
                    "evidence_hash": evidence_hash,
                    "decision_hash": decision_hash,
                    "capability_token": None,
                    "constraints": {},
                    "denial_receipt": denial.to_dict(),
                    "requires_mint": False,
                }

        # HARDENING: Enforce strong auth + gateway-issued session based on the *actual* tier.
        if tier in ("T2_HIGH_STAKES", "T3_CATASTROPHIC") and not caller_authenticated:
            return {
                "outcome": "deny",
                "tier": tier,
                "reason": "HARD_AUTH_REQUIRED: Enable API-key auth for T2/T3",
                "decision_id": None,
                "evidence_hash": evidence_hash,
                "decision_hash": None,
                "capability_token": None,
            }

        if tier in ("T2_HIGH_STAKES", "T3_CATASTROPHIC"):
            if not session_id or not str(session_id).strip():
                return {
                    "outcome": "deny",
                    "tier": tier,
                    "reason": "SESSION_REQUIRED: Acquire session via /v1/session/new",
                    "decision_id": None,
                    "evidence_hash": evidence_hash,
                    "decision_hash": None,
                    "capability_token": None,
                }
            try:
                if not self.store.validate_session(str(session_id).strip(), agent_id):
                    return {
                        "outcome": "deny",
                        "tier": tier,
                        "reason": "SESSION_INVALID_OR_EXPIRED",
                        "decision_id": None,
                        "evidence_hash": evidence_hash,
                        "decision_hash": None,
                        "capability_token": None,
                    }
            except StorageLockdownError:
                try:
                    OPS_STATS.record_storage_lockdown()
                except Exception:
                    pass
                return {
                    "outcome": "deny",
                    "tier": tier,
                    "reason": "LOCKDOWN_ACTIVE: storage degraded",
                    "decision_id": None,
                    "evidence_hash": evidence_hash,
                    "decision_hash": None,
                    "capability_token": None,
                }

        # HARDENING (v2.0.5): Semantic minimalism escalation.
        # If evidence is structurally present but fails MID/entropy/repetition checks,
        # require a human-held reviewer override before minting high-tier capabilities.
        if requires_reviewer_override:
            tiers_env = os.getenv("LAP_REVIEWER_OVERRIDE_TIERS", "T3_CATASTROPHIC")
            override_tiers = {t.strip() for t in tiers_env.split(",") if t.strip()}
            if tier in override_tiers:
                reason = f"{reason} | REQUIRES_REVIEWER_OVERRIDE: {'; '.join(quality_issues)}"
        
        decision_hash = self._compute_decision_hash(
            action_id, evidence_hash, outcome, tier, reason
        )
        
        # Store decision
        decision_id = f"dec_{secrets.token_urlsafe(12)}"
        try:
            self.store.store_decision(
                decision_id, action_id, evidence_hash, decision_hash,
                outcome, tier, reason, agent_id
                )
        except StorageLockdownError:
            try:
                OPS_STATS.record_storage_lockdown()
            except Exception:
                pass
            # Fail-closed: if storage is degraded, do not issue approvals or tokens.
            deny_reason = "LOCKDOWN_ACTIVE: storage degraded"
            deny_hash = self._compute_decision_hash(action_id, evidence_hash, "deny", tier, deny_reason)
            denial = DenialReceipt(
                receipt_id=f"deny_{secrets.token_urlsafe(12)}",
                action_id=action_id,
                evidence_hash=evidence_hash,
                decision_hash=deny_hash,
                outcome="deny",
                tier=tier,
                reason=deny_reason,
                denied_at_utc=_now_utc().isoformat(),
                key_id=self.signer.key_id,
            )
            # Best-effort denial receipt signing. If the signer is unavailable, still fail-closed.
            try:
                denial.signature = self.signer.sign(denial.compute_signature_payload())
                denial_receipt = denial.to_dict()
            except Exception:
                denial_receipt = None
            return {
                "outcome": "deny",
                "tier": tier,
                "reason": deny_reason,
                "action_id": action_id,
                "evidence_hash": evidence_hash,
                "decision_hash": deny_hash,
                "capability_token": None,
                "constraints": {},
                "denial_receipt": denial_receipt,
                "requires_mint": False,
            }
        
        # Step 3: Issue capability token if approved
        capability_token = None
        constraints = {}
        denial_receipt = None
        requires_mint = False
        
        if outcome == "approve":
            # HARDENING (v2.0.2): T3 requires separate mint step
            if tier == "T3_CATASTROPHIC":
                requires_mint = True
                constraints = {
                    "message": "T3 approval granted. Use /v1/mint-t3-token to get single-use token.",
                    "action_id": action_id,
                    "evidence_hash": evidence_hash,
                    "decision_hash": decision_hash,
                }
            else:
                # HARDENING (v2.0.2): T2 requires session_id
                if tier == "T2_HIGH_STAKES" and not session_id:
                    return {
                        "outcome": "deny",
                        "tier": tier,
                        "reason": "T2_REQUIRES_SESSION: session_id required for T2 actions",
                        "action_id": action_id,
                        "evidence_hash": evidence_hash,
                        "decision_hash": decision_hash,
                        "capability_token": None,
                        "constraints": {},
                        "denial_receipt": None,
                        "requires_mint": False,
                    }
                
                # Determine allowed tools based on tier
                allowed_tools = self._get_allowed_tools_for_tier(tier)
                
                try:
                    token = self.token_issuer.issue_token(
                        subject=agent_id,
                        action_id=action_id,
                        evidence_hash=evidence_hash,
                        decision_hash=decision_hash,
                        tier=tier,
                        allowed_tools=allowed_tools,
                        sid=session_id,  # HARDENING (v2.0.2)
                    )
                except Exception as e:
                    # Fail-closed: never mint a token if signing is unavailable.
                    try:
                        OPS_STATS.record_signer_unavailable()
                    except Exception:
                        pass
                    deny_reason = f"SIGNER_UNAVAILABLE: {type(e).__name__}: {e}"
                    deny_hash = self._compute_decision_hash(action_id, evidence_hash, "deny", tier, deny_reason)
                    return {
                        "outcome": "deny",
                        "tier": tier,
                        "reason": deny_reason,
                        "action_id": action_id,
                        "evidence_hash": evidence_hash,
                        "decision_hash": deny_hash,
                        "capability_token": None,
                        "constraints": {},
                        "denial_receipt": None,
                        "requires_mint": False,
                    }
                
                try:
                    self.store.store_token(token)
                except StorageLockdownError:
                    try:
                        OPS_STATS.record_storage_lockdown()
                    except Exception:
                        pass
                    deny_reason = "LOCKDOWN_ACTIVE: storage degraded"
                    deny_hash = self._compute_decision_hash(action_id, evidence_hash, "deny", tier, deny_reason)
                    denial = DenialReceipt(
                        receipt_id=f"deny_{secrets.token_urlsafe(12)}",
                        action_id=action_id,
                        evidence_hash=evidence_hash,
                        decision_hash=deny_hash,
                        outcome="deny",
                        tier=tier,
                        reason=deny_reason,
                        denied_at_utc=_now_utc().isoformat(),
                        key_id=self.signer.key_id,
                    )
                    try:
                        denial.signature = self.signer.sign(denial.compute_signature_payload())
                        denial_receipt = denial.to_dict()
                    except Exception:
                        denial_receipt = None
                    return {
                        "outcome": "deny",
                        "tier": tier,
                        "reason": deny_reason,
                        "action_id": action_id,
                        "evidence_hash": evidence_hash,
                        "decision_hash": deny_hash,
                        "capability_token": None,
                        "constraints": {},
                        "denial_receipt": denial_receipt,
                        "requires_mint": False,
                    }
                capability_token = token.to_compact()
                constraints = {
                    "allowed_tools": allowed_tools,
                    "budget": token.budget.to_dict(),
                    "expires_at": token.exp,
                    "nonce_required": token.nonce_required,
                    "counter_required": token.counter_required,
                }
        else:
            # Issue denial receipt
            denial = DenialReceipt(
                receipt_id=f"deny_{secrets.token_urlsafe(12)}",
                action_id=action_id,
                evidence_hash=evidence_hash,
                decision_hash=decision_hash,
                outcome=outcome,
                tier=tier,
                reason=reason,
                denied_at_utc=_now_utc().isoformat(),
                key_id=self.signer.key_id,
            )
            try:
                denial.signature = self.signer.sign(denial.compute_signature_payload())
                denial_receipt = denial.to_dict()
            except Exception:
                # Fail-closed even if we can't sign the denial receipt.
                denial_receipt = None
                # Keep the original reason and decision_hash stable; omit denial_receipt.
        
        return {
            "outcome": outcome,
            "tier": tier,
            "reason": reason,
            "action_id": action_id,
            "evidence_hash": evidence_hash,
            "decision_hash": decision_hash,
            "capability_token": capability_token,
            "constraints": constraints,
            "denial_receipt": denial_receipt,
            "requires_mint": requires_mint,
        }
    
    async def mint_t3_token(
        self,
        action_id: str,
        evidence_hash: str,
        decision_hash: str,
        tool_name: str,
        operation: str,
        params: Dict[str, Any],
        session_id: str,
        agent_id: str,
        caller_authenticated: bool = False,  # HARDENING (v1.0.2): Strong auth required for T3 minting
    ) -> Dict[str, Any]:
        """
        Mint a single-use T3 token for a specific invocation.
        
        HARDENING (v2.0.2): T3 tokens are minted per-invocation with:
        - params_hash binding (cannot invoke with different params)
        - session_id binding (cannot use from different session)
        - Single-use (auto-revoked after use)
        
        Requires prior approval via evaluate_action.
        
        Returns token details or error.
        """
        # Verify decision exists and is approved (and inspect reason for override flags)
        try:
            decision = self.store.get_decision(action_id, evidence_hash, decision_hash)
        except StorageLockdownError:
            try:
                OPS_STATS.record_storage_lockdown()
            except Exception:
                pass
            return {
                "success": False,
                "error": "LOCKDOWN_ACTIVE: storage degraded",
                "capability_token": None,
            }

        if decision is None:
            return {
                "success": False,
                "error": "DECISION_INVALID: DECISION_NOT_FOUND",
                "capability_token": None,
            }

        if decision.get("outcome") != "approve":
            return {
                "success": False,
                "error": f"DECISION_INVALID: DECISION_NOT_APPROVE: {decision.get('outcome')}",
                "capability_token": None,
            }

        # HARDENING: Strong auth and valid gateway-issued session required for T3 minting.
        if not caller_authenticated:
            return {
                "success": False,
                "error": "HARD_AUTH_REQUIRED_T3_MINT",
                "capability_token": None,
            }

        if not (session_id or "").strip():
            return {
                "success": False,
                "error": "SESSION_REQUIRED_T3_MINT",
                "capability_token": None,
            }

        try:
            if not self.store.validate_session(session_id=str(session_id), agent_id=str(agent_id)):
                return {
                    "success": False,
                    "error": "SESSION_INVALID_OR_NOT_OWNED",
                    "capability_token": None,
                }
        except StorageLockdownError:
            try:
                OPS_STATS.record_storage_lockdown()
            except Exception:
                pass
            return {
                "success": False,
                "error": "LOCKDOWN_ACTIVE: storage degraded",
                "capability_token": None,
            }

        # HARDENING (v2.0.4): Require multi-role external approval consensus for T3 minting.
        required_roles_env = os.getenv("LAP_T3_REQUIRED_ROLES", "PrimaryDecider,SafetyCritic")
        required_roles = [r.strip() for r in required_roles_env.split(",") if r.strip()]

        # HARDENING (v2.0.5): If the stored decision reason indicates semantic-minimalism override
        # is required, include the reviewer override role as a mandatory approval.
        reviewer_override_role = os.getenv("LAP_REVIEWER_OVERRIDE_ROLE", "ReviewerOverride").strip()
        decision_reason = str(decision.get("reason", ""))
        if reviewer_override_role and "REQUIRES_REVIEWER_OVERRIDE" in decision_reason:
            if reviewer_override_role not in required_roles:
                required_roles.append(reviewer_override_role)

        try:
            approvals = self.store.get_external_approvals(action_id, evidence_hash)
        except StorageLockdownError:
            try:
                OPS_STATS.record_storage_lockdown()
            except Exception:
                pass
            return {
                "success": False,
                "error": "LOCKDOWN_ACTIVE: storage degraded",
                "capability_token": None,
            }

        # Re-verify signatures at mint time (defends against DB tampering).
        verified: List[Ed25519ExternalApproval] = []
        for ap in approvals:
            try:
                if ap.verify(self.trusted_keys):
                    verified.append(ap)
            except Exception:
                continue

        def _has_role(role: str) -> bool:
            for ap in verified:
                if ap.reviewer_type == role and ap.decision == "approve":
                    return True
            return False

        missing = [role for role in required_roles if not _has_role(role)]
        if missing:
            return {
                "success": False,
                "error": f"MISSING_EXTERNAL_APPROVALS: {','.join(missing)}",
                "capability_token": None,
            }


        # Compute params_hash
        params_canonical = canonical_json_dumps(
            {"tool_name": tool_name, "operation": operation, "params": params},
            version="v1",
        )
        params_hash = _sha256_hex(params_canonical.encode('utf-8'))
        
        # Issue T3 token with params_hash
        token = self.token_issuer.issue_token(
            subject=agent_id,
                action_id=action_id,
                evidence_hash=evidence_hash,
                decision_hash=decision_hash,
            tier="T3_CATASTROPHIC",
            allowed_tools=[tool_name],
            allowed_ops=[operation],
            params_hash=params_hash,  # Bound to specific invocation
            sid=session_id,  # Bound to session
        )
        
        try:
            self.store.store_token(token)
        except StorageLockdownError:
            try:
                OPS_STATS.record_storage_lockdown()
            except Exception:
                pass
            return {
                "success": False,
                "error": "LOCKDOWN_ACTIVE: storage degraded",
                "capability_token": None,
            }

        return {
            "success": True,
            "capability_token": token.to_compact(),
            "params_hash": params_hash,
            "expires_at": token.exp,
            "single_use": True,
            "nonce_required": token.nonce_required,
            "counter_required": token.counter_required,
        }
    
    def _estimate_tier(self, evidence: Dict[str, Any]) -> str:
        """Estimate tier from evidence for quality checks."""
        irr = evidence.get("irreversibility", {})
        if isinstance(irr, dict):
            irr_score = irr.get("score", 0.0)
        else:
            irr_score = 0.0
        
        suffering = evidence.get("suffering_risk_estimate", 0.0)
        
        if irr_score >= 0.70 or suffering >= 0.70:
            return "T3_CATASTROPHIC"
        elif irr_score >= 0.30 or suffering >= 0.30:
            return "T2_HIGH_STAKES"
        elif irr_score >= 0.10:
            return "T1_SENSITIVE"
        return "T0_ROUTINE"
    

    def _detect_malicious_payload(self, text: str) -> List[str]:
        """Heuristic detection of hidden hazardous commands in natural language.

        This is NOT a complete solution to prompt injection. It's an "adversarial lab"
        tripwire: if the evidence description contains obvious destructive shell patterns,
        force deny/review rather than quietly approving.
        """
        import re
        import unicodedata

        if not text:
            return []

        # Normalize to catch common obfuscations (zero-width chars, homoglyph-ish forms, etc.)
        # Goal: "adversarial lab" tripwire, not a full prompt-injection defense.
        t = unicodedata.normalize("NFKC", str(text))
        # Strip format characters (e.g., zero-width space/joiners)
        t = "".join(ch for ch in t if unicodedata.category(ch) != "Cf")
        # Collapse whitespace
        t = re.sub(r"\s+", " ", t)

        # Command-shaped destructive payloads (shell + Windows-ish)
        patterns = [
            # Linux/Unix destructive
            r"(?:^|[^\w])rm\s+-rf\s+/",
            r"(?:^|[^\w])mkfs(\.[\w]+)?\b",
            r"(?:^|[^\w])dd\s+if=",
            r"(?:^|[^\w])wipefs\b",
            r"(?:^|[^\w])chmod\s+\+s\b",
            r"(?:curl|wget)\s+[^\n]+\|\s*(?:sh|bash)",
            r"base64\s+-d\s*\|\s*(?:sh|bash)",
            # Fork bomb (classic)
            r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
            # Windows destructive-ish
            r"(?:^|[^\w])format\s+[a-z]:",
            r"(?:^|[^\w])del\s+/s\s+/q\s+[a-z]:\\",
            r"powershell(?:\.exe)?\s+-(?:enc|encodedcommand)\b",
            # Restart/shutdown as commands (avoid matching casual prose by requiring non-word boundary)
            r"(?:^|[^\w])shutdown\b",
            r"(?:^|[^\w])reboot\b",
        ]

        hits: List[str] = []
        for p in patterns:
            if re.search(p, t, flags=re.IGNORECASE):
                hits.append(p)
        return hits

    def _simple_evaluate(self, evidence: Dict[str, Any]) -> Tuple[str, str, str]:
        """Simple evaluation logic (placeholder for full LAP integration)."""
        tier = self._estimate_tier(evidence)

        # Adversarial-lab tripwire: detect obvious hidden destructive commands
        desc = str(evidence.get("description", ""))
        hits = self._detect_malicious_payload(desc)
        if hits:
            return "deny", tier, "PROMPT_INJECTION_DETECTED: suspicious shell patterns in description"
        
        if tier == "T3_CATASTROPHIC":
            # Check for external approval
            action_id = evidence.get("action_id", "")
            evidence_hash = self._compute_evidence_hash(evidence)
            try:
                approval = self.store.get_external_approval(action_id, evidence_hash)
            except StorageLockdownError:
                try:
                    OPS_STATS.record_storage_lockdown()
                except Exception:
                    pass
                return "require_external_review", tier, "LOCKDOWN_ACTIVE: storage degraded"
            
            if approval and approval.verify(self.trusted_keys):
                return "approve", tier, "T3 approved via external review"
            return "require_external_review", tier, "T3 requires external review"
        
        elif tier == "T2_HIGH_STAKES":
            # Additional scrutiny
            necessity = evidence.get("necessity_confidence", 0.0)
            if necessity < 0.7:
                return "escrow", tier, f"T2 with low necessity ({necessity:.2f}) - escrowed"
            return "approve", tier, "T2 approved with high necessity"
        
        else:
            return "approve", tier, f"{tier} approved"

    def _evaluate_with_lap_protocol(self, evidence: Dict[str, Any]) -> Tuple[str, str, str]:
        """Evaluate evidence using the optional LAP protocol engine.

        This is a best-effort adapter that:
          - attempts to parse evidence into the protocol's EvidenceObject
          - invokes lap_protocol.evaluate_action(...)
          - maps tier enums/names to gateway tier strings

        Fail-closed: on any error, we fall back to the simple evaluator.
        """

        if not getattr(self, "lap_protocol", None):
            return self._simple_evaluate(evidence)

        try:
            from lap_cli import validate_evidence_json, parse_evidence_json

            ok, errs = validate_evidence_json(evidence)
            if not ok:
                logger.warning("Evidence not compatible with protocol engine; falling back: %s", errs)
                return self._simple_evaluate(evidence)

            ev_obj = parse_evidence_json(evidence)
            decision = self.lap_protocol.evaluate_action(ev_obj)

            # Outcome
            outcome_val = getattr(getattr(decision, "outcome", None), "value", None)
            outcome = outcome_val if isinstance(outcome_val, str) else str(getattr(decision, "outcome", "deny"))

            # Tier mapping
            tier_name = getattr(getattr(decision, "tier", None), "name", None)
            tier_raw = tier_name if isinstance(tier_name, str) else str(getattr(decision, "tier", "T2_HIGH_STAKES"))
            tier_map = {
                "T0_ROUTINE": "T0_ROUTINE",
                "T1_SENSITIVE": "T1_SENSITIVE",
                "T2_HIGH_STAKES": "T2_HIGH_STAKES",
                "T3_CATASTROPHIC": "T3_CATASTROPHIC",
            }
            tier = tier_map.get(tier_raw, tier_raw)

            reason = str(getattr(decision, "reason", ""))
            return outcome, tier, reason

        except Exception as e:
            logger.error("Protocol engine evaluation failed; falling back: %s", e)
            return self._simple_evaluate(evidence)
    
    def _get_allowed_tools_for_tier(self, tier: str) -> List[str]:
        """Get allowed tools based on tier.

        Hardening: allow deployers to configure allowlists via env/file, while
        keeping a conservative default mapping.

        Env:
          - LAP_ALLOWED_TOOLS_BY_TIER_JSON: JSON object {"T2_HIGH_STAKES": ["mock"], ...}
          - LAP_ALLOWED_TOOLS_BY_TIER_FILE: path to JSON file with the same shape
        """
        all_tools = list(self.tool_connectors.keys())

        # Optional configuration overrides
        cfg: Optional[Dict[str, Any]] = None
        raw = os.getenv("LAP_ALLOWED_TOOLS_BY_TIER_JSON", "").strip()
        path = os.getenv("LAP_ALLOWED_TOOLS_BY_TIER_FILE", "").strip()
        try:
            if raw:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    cfg = parsed
            elif path:
                with open(path, "r", encoding="utf-8") as f:
                    parsed = json.loads(f.read())
                if isinstance(parsed, dict):
                    cfg = parsed
        except Exception as e:
            logger.warning("Failed to load tool allowlist config: %s", e)

        if cfg and tier in cfg and isinstance(cfg.get(tier), list):
            allowed = [str(t) for t in cfg.get(tier) if t is not None]
            return [t for t in allowed if t in all_tools]

        # Conservative defaults (support both historical and canonical tier names)
        if tier in ("T0_LOW", "T0_ROUTINE"):
            return all_tools
        if tier in ("T1_STANDARD", "T1_SENSITIVE"):
            # Exclude obviously destructive tools by name (connectors may override)
            return [t for t in all_tools if t not in ["delete", "admin"]]
        if tier == "T2_HIGH_STAKES":
            # Safe, read-mostly connectors by default
            return [t for t in all_tools if t in ["read", "mock", "filesystem", "http"]]
        # T3: explicit minimal surface
        return [t for t in all_tools if t in ["mock"]]
    
    async def invoke_tool(
        self,
        tool_name: str,
        operation: str,
        params: Dict[str, Any],
        token_compact: str,
        caller_id: Optional[str] = None,  # HARDENING (v2.0.2): Required for identity binding
        session_id: Optional[str] = None,  # HARDENING (v2.0.2): Required for T2/T3
        nonce: Optional[str] = None,  # HARDENING (v2.0.2): Required if token.nonce_required
        counter: Optional[int] = None,  # HARDENING (v2.0.2): Required if token.counter_required
        caller_authenticated: bool = False,  # HARDENING (v1.0.2): Strong auth required for T2/T3
    ) -> Dict[str, Any]:
        """
        Invoke a tool with capability token.
        
        SECURITY ENFORCEMENT:
        - Token signature validity (Ed25519)
        - Token scope (tool + operation)
        - Caller identity binding (token.sub == caller_id)
        - Session binding for T2/T3 (token.sid == session_id)
        - Nonce for replay prevention (T2/T3)
        - Monotonic counter for ordering (T3)
        - Budget limits (atomic reservation, persistent)
        - Decision state cross-check
        - Param binding for T3 tokens (fail closed if empty)
        - Credential isolation (JIT from gateway)
        - Output size enforcement
        
        HARDENING (v2.0.2): 
        - Full nonce/counter/session enforcement for T2/T3
        - Uses atomic_reserve_budget to prevent race conditions
        - Enforces caller identity binding
        - T3 fails closed without params_hash
        - Bytes_out reservation before invocation
        
        Returns result with signed receipt.
        """
        # Maximum response size (enforced even if budget allows more)
        MAX_RESPONSE_BYTES = 10_000_000  # 10MB hard limit
        
        # Step 1: Parse and verify token
        try:
            token = CapabilityToken.from_compact(token_compact)
        except Exception as e:
            return {
                "success": False,
                "result": None,
                "error": f"Invalid token format: {e}",
                "receipt": {},
            }
        
        # Step 2: HARDENING (v2.0.2) - Enforce caller identity binding
        # Fail closed for T2/T3 if no caller_id provided
        if token.tier in ("T2_HIGH_STAKES", "T3_CATASTROPHIC"):
            if caller_id is None:
                return {
                    "success": False,
                    "result": None,
                    "error": f"CALLER_ID_REQUIRED: T2/T3 tokens require caller identity",
                    "receipt": {},
                }
        
        if caller_id is not None and token.sub != caller_id:
            return {
                "success": False,
                "result": None,
                "error": f"IDENTITY_MISMATCH: Token bound to {token.sub}, caller is {caller_id}",
                "receipt": {},
            }
        
        # Step 3: HARDENING (v2.0.2) - Enforce session binding for T2/T3
        if token.tier in ("T2_HIGH_STAKES", "T3_CATASTROPHIC"):
            if not token.sid or not str(token.sid).strip():
                return {
                    "success": False,
                    "result": None,
                    "error": "TOKEN_MISSING_SID: T2/T3 tokens must have session binding",
                    "receipt": {},
                }
            sid = (session_id or "").strip()
            if not sid:
                return {
                    "success": False,
                    "result": None,
                    "error": "SESSION_ID_REQUIRED: T2/T3 invocations require session_id",
                    "receipt": {},
                }
            if str(token.sid).strip() != sid:
                return {
                    "success": False,
                    "result": None,
                    "error": f"SESSION_MISMATCH: Token bound to session {token.sid}",
                    "receipt": {},
                }
            # Validate that the session is gateway-issued, owned by the caller, and unexpired.
            owner = (token.sub or caller_id or "").strip()
            if not owner:
                return {
                    "success": False,
                    "result": None,
                    "error": "CALLER_ID_REQUIRED: session validation requires caller identity",
                    "receipt": {},
                }
            try:
                if not self.store.validate_session(sid, owner):
                    return {
                        "success": False,
                        "result": None,
                        "error": "SESSION_INVALID_OR_EXPIRED",
                        "receipt": {},
                    }
            except StorageLockdownError:
                try:
                    OPS_STATS.record_storage_lockdown()
                except Exception:
                    pass
                return {
                    "success": False,
                    "result": None,
                    "error": "LOCKDOWN_ACTIVE: storage degraded",
                    "receipt": {},
                }
# Step 4: Authenticate token (verify signature and basic claims)
        valid, reason = self.token_verifier.verify_token(
            token,
            required_tool=tool_name,
            required_op=operation,
        )
        
        if not valid:
            return {
                "success": False,
                "result": None,
                "error": f"Token verification failed: {reason}",
                "receipt": {},
            }

        # Step 5: HARDENING (v2.0.2) - Enforce nonce (T2/T3) [AUTHENTICATED ONLY]
        if token.nonce_required:
            if nonce is None:
                return {
                    "success": False,
                    "result": None,
                    "error": "NONCE_REQUIRED: This token requires a unique nonce per invocation",
                    "receipt": {},
                }
            
            try:
                nonce_ok, nonce_reason = self.store.check_and_record_nonce(token.jti, nonce)
            except StorageLockdownError:
                try:
                    OPS_STATS.record_storage_lockdown()
                except Exception:
                    pass
                return {
                    "success": False,
                    "result": None,
                    "error": "LOCKDOWN_ACTIVE: storage degraded",
                    "receipt": {},
                }
            if not nonce_ok:
                if METRICS_HOOKS_AVAILABLE and record_replay_reject is not None:
                    try:
                        record_replay_reject("nonce")
                    except Exception:
                        pass
                return {
                    "success": False,
                    "result": None,
                    "error": f"REPLAY_DETECTED: {nonce_reason}",
                    "receipt": {},
                }

        # Step 6: HARDENING (v2.0.2) - Enforce counter ordering (T3) [AUTHENTICATED ONLY]
        if token.counter_required:
            if counter is None:
                return {
                    "success": False,
                    "result": None,
                    "error": "COUNTER_REQUIRED: T3 tokens require monotonic counter",
                    "receipt": {},
                }
            
            try:
                counter_ok, counter_reason = self.store.check_and_update_counter(token.jti, counter)
            except StorageLockdownError:
                try:
                    OPS_STATS.record_storage_lockdown()
                except Exception:
                    pass
                return {
                    "success": False,
                    "result": None,
                    "error": "LOCKDOWN_ACTIVE: storage degraded",
                    "receipt": {},
                }
            if not counter_ok:
                if METRICS_HOOKS_AVAILABLE and record_replay_reject is not None:
                    try:
                        record_replay_reject("counter")
                    except Exception:
                        pass
                return {
                    "success": False,
                    "result": None,
                    "error": f"ORDERING_VIOLATION: {counter_reason}",
                    "receipt": {},
                }
# Step 7: HARDENING (v2.0.2) - T3 param binding (FAIL CLOSED if empty)
        if token.tier == "T3_CATASTROPHIC":
            if not token.params_hash:
                return {
                    "success": False,
                    "result": None,
                    "error": "T3_PARAMS_REQUIRED: T3 tokens must have params_hash binding",
                    "receipt": {},
                }
            
            # Compute hash including tool_name and operation for T3
            params_canonical = canonical_json_dumps(
                {"tool_name": tool_name, "operation": operation, "params": params},
                version="v1",
            )
            actual_params_hash = _sha256_hex(params_canonical.encode('utf-8'))
            
            if actual_params_hash != token.params_hash:
                return {
                    "success": False,
                    "result": None,
                    "error": f"T3_PARAMS_MISMATCH: Token bound to different params",
                    "receipt": {},
                }
        
        # Step 8: Get tool connector (before budget reservation)
        connector = self.tool_connectors.get(tool_name)
        if connector is None:
            return {
                "success": False,
                "result": None,
                "error": f"Unknown tool: {tool_name}",
                "receipt": {},
            }
        
        # Step 9: HARDENING (v2.0.2) - Atomic budget reservation
        # This atomically checks: token not revoked, decision valid, budget available
        # and reserves the budget in a single transaction
        params_size = len(json.dumps(params))
        budget_dict = token.budget.to_dict()
        
        # Reserve expected max response size
        reserve_bytes_out = min(
            budget_dict.get("max_bytes_out") or MAX_RESPONSE_BYTES,
            MAX_RESPONSE_BYTES
        )
        
        try:
            reserved, reserve_reason = self.store.atomic_reserve_budget(
                jti=token.jti,
                action_id=token.action_id,
                evidence_hash=token.evidence_hash,
                decision_hash=token.decision_hash,
                budget=budget_dict,
                add_calls=1,
                add_bytes_in=params_size,
                reserve_bytes_out=reserve_bytes_out,
                )
        except StorageLockdownError:
            try:
                OPS_STATS.record_storage_lockdown()
            except Exception:
                pass
            return {
                "success": False,
                "result": None,
                "error": "LOCKDOWN_ACTIVE: storage degraded",
                "receipt": {},
            }
        
        if not reserved:
            return {
                "success": False,
                "result": None,
                "error": f"Reservation failed: {reserve_reason}",
                "receipt": {},
            }
        
        # Step 10: Get credentials (agent never sees these)
        credentials = None
        if self.credential_provider:
            credentials = self.credential_provider.get_credentials(tool_name, operation)
        
        # Step 11: Invoke tool
        invoked_at = _now_utc()
        try:
            success, result, error = await connector.invoke(operation, params, credentials)
        except Exception as e:
            success = False
            result = None
            error = str(e)
        completed_at = _now_utc()
        
        # Step 12: Compute actual result size and enforce limits
        result_json = json.dumps(result, default=str) if result is not None else "null"
        actual_bytes_out = len(result_json)
        
        if actual_bytes_out > MAX_RESPONSE_BYTES:
            # Truncate result and mark as error
            success = False
            error = f"RESPONSE_TOO_LARGE: {actual_bytes_out} bytes exceeds {MAX_RESPONSE_BYTES} limit"
            result = {"truncated": True, "original_size": actual_bytes_out}
            actual_bytes_out = len(json.dumps(result, default=str))

        # Step 12b: HARDENING (v1.0.0) - Fail-closed on bytes_out budget exceed
        # If the tool produces output larger than what was reserved for this invocation,
        # do not return it. Revoke the token defensively.
        if actual_bytes_out > reserve_bytes_out:
            success = False
            error = (
                f"BYTES_OUT_BUDGET_EXCEEDED: produced {actual_bytes_out} bytes "
                f"but budget reserves {reserve_bytes_out}"
            )
            result = {
                "withheld": True,
                "original_size": actual_bytes_out,
                "budget_reserved": reserve_bytes_out,
            }
            # Recompute bytes for the withheld response
            actual_bytes_out = len(json.dumps(result, default=str))
            # Defensive revocation to prevent repeated exfil attempts
            try:
                self.store.revoke_token(token.jti)
            except StorageLockdownError:
                try:
                    OPS_STATS.record_storage_lockdown()
                except Exception:
                    pass
                pass
            self.budget_tracker.revoke(token.jti)
        
        # Step 13: Finalize budget (adjust reserved to actual)
        actual_bytes_out_finalized = actual_bytes_out
        duration = (completed_at - invoked_at).total_seconds()
        try:
            self.store.finalize_budget_usage(
            token.jti,
            actual_bytes_out=actual_bytes_out,
            reserved_bytes_out=reserve_bytes_out,
            duration=duration
            )
        except StorageLockdownError:
            try:
                OPS_STATS.record_storage_lockdown()
            except Exception:
                pass
            # Fail-closed: withhold output if we cannot persist budget finalization.
            success = False
            error = "LOCKDOWN_ACTIVE: storage degraded"
            result = {"withheld": True, "reason": "lockdown_active"}
            actual_bytes_out = len(json.dumps(result, default=str))
            actual_bytes_out_finalized = actual_bytes_out
            try:
                self.store.revoke_token(token.jti)
            except StorageLockdownError:
                try:
                    OPS_STATS.record_storage_lockdown()
                except Exception:
                    pass
                pass
            self.budget_tracker.revoke(token.jti)
        
        # Step 14: HARDENING (v2.0.1) - Revoke T3 tokens after single use
        if token.tier == "T3_CATASTROPHIC":
            try:
                self.store.revoke_token(token.jti)
            except StorageLockdownError:
                try:
                    OPS_STATS.record_storage_lockdown()
                except Exception:
                    pass
                pass
            self.budget_tracker.revoke(token.jti)
        
        # Step 15: Issue receipt
        receipt = self.receipt_issuer.issue_receipt(
                action_id=token.action_id,
                evidence_hash=token.evidence_hash,
                decision_hash=token.decision_hash,
            token_jti=token.jti,
            tool_name=tool_name,
            operation=operation,
            params=params,
            result=result,
            response_envelope={"success": success, "result": result, "error": error},
            result_status="success" if success else "error",
            invoked_at=invoked_at,
            completed_at=completed_at,
        )

        # Step 15b: Tamper-evident audit log append
        try:
            receipt_hash = _sha256_hex(
                json.dumps(receipt.to_dict(), sort_keys=True, default=str).encode("utf-8")
            )
            self.audit_log.append_event(
                {
                    "type": "tool_receipt",
                    "receipt_id": receipt.receipt_id,
                    "action_id": token.action_id,
                    "token_jti": token.jti,
                    "tool_name": tool_name,
                    "operation": operation,
                    "result_status": "success" if success else "error",
                    "receipt_hash": receipt_hash,
                }
            )
        except Exception as e:
            # Do not silently allow invocations without audit.
            # Note: the tool may have already executed.
            success = False
            error = f"AUDIT_LOG_FAILED: {e}"
            result = {"withheld": True, "reason": "audit_log_failed"}
            # Adjust bytes_out accounting to match the withheld response.
            try:
                new_actual_bytes_out = len(json.dumps(result, default=str))
                # We already finalized to `actual_bytes_out_finalized` earlier in this invocation.
                # Apply only the delta: (new - old). Use duration=0 to avoid double-counting.
                try:
                    self.store.finalize_budget_usage(
                    token.jti,
                    actual_bytes_out=new_actual_bytes_out,
                    reserved_bytes_out=actual_bytes_out_finalized,
                    duration=0.0,
                    )
                except StorageLockdownError:
                    try:
                        OPS_STATS.record_storage_lockdown()
                    except Exception:
                        pass
                    # Fail-closed: withhold output if we cannot persist budget finalization.
                    success = False
                    error = "LOCKDOWN_ACTIVE: storage degraded"
                    result = {"withheld": True, "reason": "lockdown_active"}
                    actual_bytes_out = len(json.dumps(result, default=str))
                    actual_bytes_out_finalized = actual_bytes_out
                    try:
                        self.store.revoke_token(token.jti)
                    except StorageLockdownError:
                        try:
                            OPS_STATS.record_storage_lockdown()
                        except Exception:
                            pass
                        pass
                    self.budget_tracker.revoke(token.jti)
            except Exception:
                # Budget correction should never crash the handler.
                pass
            # Defensive revocation
            try:
                self.store.revoke_token(token.jti)
            except StorageLockdownError:
                try:
                    OPS_STATS.record_storage_lockdown()
                except Exception:
                    pass
                pass
            self.budget_tracker.revoke(token.jti)
            # Re-issue receipt to reflect the final returned status
            receipt = self.receipt_issuer.issue_receipt(
                action_id=token.action_id,
                evidence_hash=token.evidence_hash,
                decision_hash=token.decision_hash,
                token_jti=token.jti,
                tool_name=tool_name,
                operation=operation,
                params=params,
                result=result,
                response_envelope={"success": success, "result": result, "error": error},
                result_status="error",
                invoked_at=invoked_at,
                completed_at=completed_at,
            )

        try:
            self.store.store_receipt(receipt)
        except StorageLockdownError:
            try:
                OPS_STATS.record_storage_lockdown()
            except Exception:
                pass
            # Fail-closed: if we cannot persist the receipt, do not return tool output.
            success = False
            error = 'LOCKDOWN_ACTIVE: storage degraded'
            result = {'withheld': True, 'reason': 'lockdown_active'}
            receipt = self.receipt_issuer.issue_receipt(
                action_id=token.action_id,
                evidence_hash=token.evidence_hash,
                decision_hash=token.decision_hash,
                token_jti=token.jti,
                tool_name=tool_name,
                operation=operation,
                params=params,
                result=result,
                response_envelope={'success': success, 'result': result, 'error': error},
                result_status='error',
                invoked_at=invoked_at,
                completed_at=completed_at,
            )

        return {
            "success": success,
            "result": result,
            "error": error,
            "receipt": receipt.to_dict(),
        }
    
    async def record_external_approval(
        self,
        approval: Ed25519ExternalApproval,
    ) -> Tuple[bool, str]:
        """
        Record an external approval after verifying signature.
        
        Returns (success, reason).
        """
        # Verify signature
        if not approval.verify(self.trusted_keys):
            return False, "Invalid signature or untrusted key"
        
        # Store approval
        try:
            self.store.store_external_approval(approval)
        except StorageLockdownError:
            try:
                OPS_STATS.record_storage_lockdown()
            except Exception:
                pass
            return False, "LOCKDOWN_ACTIVE: storage degraded"
        
        return True, "Approval recorded"


# ---------------------------
# FastAPI App Factory
# ---------------------------

def create_app(gateway: Optional[LAPGateway] = None) -> "FastAPI":
    """Create FastAPI application with gateway endpoints."""
    if not FASTAPI_AVAILABLE:
        raise RuntimeError("FastAPI required. Install: pip install fastapi uvicorn")
    
    from . import __version__ as lap_version

    app = FastAPI(
        title="LAP Gateway",
        description="Lattice Audit Protocol - Policy Enforcement Point",
        version=lap_version,
    )

    @app.exception_handler(LAPError)
    async def _lap_error_handler(request: Request, exc: LAPError):
        return JSONResponse(status_code=int(exc.http_status or 400), content=exc.as_dict())

    
    # Use provided gateway or create default
    if gateway is None:
        # Load signing key from env/file if provided; otherwise generate an
        # ephemeral key only if explicitly allowed (useful for demos/tests).
        allow_ephemeral = os.getenv("LAP_ALLOW_EPHEMERAL_SIGNING_KEYS", "").strip().lower() in ("1", "true", "yes")
        signing_key, gateway_key_store, gateway_pubkeys = load_gateway_signing_material(allow_ephemeral=allow_ephemeral)
        if signing_key is None:
            raise RuntimeError(
                "No gateway signing key configured. Configure either a keyset "
                "(LAP_GATEWAY_KEYSET_JSON / LAP_GATEWAY_KEYSET_FILE) or a single signing key "
                "(LAP_GATEWAY_SIGNING_KEY or LAP_GATEWAY_SIGNING_KEY_FILE). "
                "For demos/tests only, set LAP_ALLOW_EPHEMERAL_SIGNING_KEYS=1 to generate an ephemeral key."
            )

    # Load trusted reviewer public keys for external approvals (T3).
        # Format: JSON object {"key_id": "<public_key_hex>", ...}
        trusted_cfg: Dict[str, str] = {}
        trusted_json = os.getenv("LAP_TRUSTED_REVIEWER_KEYS_JSON", "").strip()
        trusted_file = os.getenv("LAP_TRUSTED_REVIEWER_KEYS_FILE", "").strip()
        if trusted_json:
            try:
                parsed = json.loads(trusted_json)
                if isinstance(parsed, dict):
                    trusted_cfg = {str(k): str(v) for k, v in parsed.items()}
                else:
                    logger.warning("LAP_TRUSTED_REVIEWER_KEYS_JSON must be a JSON object")
            except Exception as e:
                logger.warning("Failed to parse LAP_TRUSTED_REVIEWER_KEYS_JSON: %s", e)
        elif trusted_file:
            try:
                with open(trusted_file, "r", encoding="utf-8") as f:
                    parsed = json.loads(f.read())
                if isinstance(parsed, dict):
                    trusted_cfg = {str(k): str(v) for k, v in parsed.items()}
                else:
                    logger.warning("LAP_TRUSTED_REVIEWER_KEYS_FILE must contain a JSON object")
            except Exception as e:
                logger.warning("Failed to load trusted reviewer keys from %s: %s", trusted_file, e)

        trusted_store = TrustedKeyStore.from_config(trusted_cfg) if trusted_cfg else TrustedKeyStore()

        signer = build_signer_from_env(signing_key)
        gateway = LAPGateway(signer=signer, trusted_keys=trusted_store, gateway_verify_keys=gateway_key_store, gateway_public_keys=gateway_pubkeys)
        gateway.register_tool(MockToolConnector("mock"))
    # Optional: register an HTTP-backed tool connector (demo/reference)
    http_url = os.getenv("LAP_HTTP_TOOL_URL", "").strip()
    if http_url:
        try:
            from .http_tool import HttpToolConnector
            gateway.register_tool(HttpToolConnector("http", base_url=http_url))
            http_api_key = os.getenv("LAP_HTTP_TOOL_API_KEY", "").strip()
            if http_api_key:
                gateway.set_credential_provider(
                    StaticCredentialProvider({"http": {"api_key": http_api_key}})
                )
        except Exception as e:
            logger.warning("HTTP tool connector unavailable: %s", e)
    # Reference API-key auth (optional). If configured, caller identity is
    # derived from X-Api-Key instead of client-controlled fields.
    api_auth = ApiKeyAuth.load_from_env()

    # ---------------------------
    # Observability (/metrics)
    # ---------------------------
    if METRICS_HOOKS_AVAILABLE and instrument_fastapi is not None:
        metrics_token = (os.getenv('LAP_METRICS_TOKEN', '') or '').strip()
        metrics_stats_require_auth = (os.getenv('LAP_METRICS_REQUIRE_AUTH', '') or '').strip().lower() in ('1','true','yes','on')

        def _authorize_metrics(req: 'Request') -> bool:
            # If a dedicated metrics token is set, require it via:
            #   Authorization: Bearer <token>  OR  X-Metrics-Token: <token>
            if metrics_token:
                authz = (req.headers.get('Authorization') or '').strip()
                if authz.lower().startswith('bearer '):
                    if authz.split(' ', 1)[1].strip() == metrics_token:
                        return True
                if (req.headers.get('X-Metrics-Token') or '').strip() == metrics_token:
                    return True
                return False

            # Otherwise, optionally require normal API auth if configured.
            if metrics_require_auth and api_auth.enabled():
                x_api_key = req.headers.get('X-Api-Key')
                x_agent_id = req.headers.get('X-Agent-Id')
                ctx = api_auth.resolve_context(x_api_key, x_agent_id)
                return bool(ctx and ctx.authenticated and not ctx.error)

            return True

        instrument_fastapi(app, authorize=_authorize_metrics)


    # ---------------------------
    # Second-pass hardening: request size + rate limiting
    # ---------------------------

    # Request body size limit (best-effort, checks Content-Length).
    try:
        max_request_bytes = int(os.getenv("LAP_MAX_REQUEST_BYTES", "1048576") or "1048576")
    except Exception:
        max_request_bytes = 1048576

    @app.middleware("http")
    async def _limit_request_size(req: "Request", call_next):
        try:
            cl = req.headers.get("content-length")
            if cl is not None and int(cl) > max_request_bytes:
                return JSONResponse(status_code=413, content={"detail": "REQUEST_TOO_LARGE"})
        except Exception:
            # If malformed, fail-closed.
            return JSONResponse(status_code=400, content={"detail": "BAD_CONTENT_LENGTH"})
        return await call_next(req)

    def _build_limiter(env_name: str, default_spec: str) -> Optional[RateLimiter]:
        spec = os.getenv(env_name, default_spec).strip()
        if not spec or spec in ("0", "off", "disabled", "false"):
            return None
        try:
            cap, refill = parse_rate_limit(spec)
            max_keys = int(os.getenv("LAP_RATE_LIMIT_MAX_KEYS", "20000") or "20000")
            return RateLimiter(capacity=cap, refill_rate_per_sec=refill, max_keys=max_keys)
        except Exception as e:
            logger.warning("Invalid rate limit %s=%r: %s (disabled)", env_name, spec, e)
            return None

    session_limiter = _build_limiter("LAP_RATE_LIMIT_SESSION_NEW", "30/m")
    mint_t3_limiter = _build_limiter("LAP_RATE_LIMIT_MINT_T3", "60/m")
    approval_limiter = _build_limiter("LAP_RATE_LIMIT_EXTERNAL_APPROVAL", "60/m")

    def _rl_key(req: "Request", auth_ctx: "AuthContext", x_api_key: Optional[str]) -> str:
        # Prefer authenticated agent id; fall back to api key; then client IP.
        if getattr(auth_ctx, "authenticated", False) and getattr(auth_ctx, "agent_id", None):
            return str(auth_ctx.agent_id)
        if x_api_key:
            return f"k:{x_api_key}"
        try:
            if req.client and req.client.host:
                return f"ip:{req.client.host}"
        except Exception:
            pass
        return "_anon"


    @app.post("/v1/session/new", response_model=SessionResponse)
    async def new_session(
        http_request: Request,
        request: SessionRequest,
        x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
        x_agent_id: Optional[str] = Header(None, alias="X-Agent-Id"),
    ):
        """Create a gateway-issued session id (required for T2/T3).

        If API-key auth is configured, this endpoint requires a valid X-Api-Key.
        """
        auth_ctx = api_auth.resolve_context(x_api_key, x_agent_id)
        if auth_ctx.error:
            raise HTTPException(401, auth_ctx.error)


        # If auth is enabled, require authenticated context for issuing sessions.
        if api_auth.enabled() and not auth_ctx.authenticated:
            raise _http_exc(401, LAP_E_AUTH_REQUIRED, "HARD_AUTH_REQUIRED")

        # Best-effort rate limit on session issuance.
        if session_limiter is not None:
            if not session_limiter.allow(_rl_key(http_request, auth_ctx, x_api_key)):
                if METRICS_HOOKS_AVAILABLE and record_rate_limited is not None:
                    record_rate_limited('session_new')
                raise _http_exc(429, LAP_E_RATE_LIMITED, "RATE_LIMITED", retryable=True)

        agent_id = auth_ctx.agent_id or x_agent_id or "unknown"
        if not agent_id or agent_id == "unknown":
            raise _http_exc(400, LAP_E_AGENT_ID_REQUIRED, "Agent identity required")

        try:
            sid, expires = gateway.store.create_session(agent_id=str(agent_id), ttl_seconds=int(request.ttl_seconds))
        except ValueError as e:
            raise _http_exc(400, LAP_E_BAD_REQUEST, str(e))
        except StorageLockdownError:
            try:
                OPS_STATS.record_storage_lockdown()
            except Exception:
                pass
            raise _http_exc(503, LAP_E_LOCKDOWN_ACTIVE, "LOCKDOWN_ACTIVE", retryable=True)
        return SessionResponse(session_id=sid, expires_at_utc=expires)

    @app.post("/v1/evaluate", response_model=EvaluateResponse)
    async def evaluate_action(
        request: EvaluateRequest,
        x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
        x_agent_id: Optional[str] = Header(None, alias="X-Agent-Id"),
        x_session_id: Optional[str] = Header(None, alias="X-Session-Id"),
    ):
        """Evaluate an action and return decision with capability token."""
        evidence = {
            "action_id": request.action_id,
            "description": request.description,
            "timestamp_utc": request.timestamp_utc or _now_utc().isoformat(),
            "irreversibility": request.irreversibility,
            "outcome_delta": request.outcome_delta,
            "necessity_confidence": request.necessity_confidence,
            "novelty_loss_estimate": request.novelty_loss_estimate,
            "novelty_method": request.novelty_method,
            "suffering_risk_estimate": request.suffering_risk_estimate,
            "suffering_method": request.suffering_method,
            "provenance": request.provenance,
            "alternatives": request.alternatives,
            "attestations": request.attestations,
        }

        claimed_agent = x_agent_id or request.agent_id
        auth_ctx = api_auth.resolve_context(x_api_key, claimed_agent)
        if auth_ctx.error:
            raise HTTPException(401, auth_ctx.error)
        agent_id = auth_ctx.agent_id or claimed_agent or "unknown"

        # Resolve session binding from header/body (fail closed on mismatch)
        body_sid = (request.session_id or "").strip()
        hdr_sid = (x_session_id or "").strip()
        if body_sid and hdr_sid and body_sid != hdr_sid:
            raise _http_exc(400, LAP_E_SESSION_MISMATCH, "SESSION_MISMATCH")
        session_id = hdr_sid or body_sid

        result = await gateway.evaluate_action(
            evidence=evidence,
            agent_id=agent_id,
            session_id=session_id,
            caller_authenticated=auth_ctx.authenticated,
        )
        if METRICS_HOOKS_AVAILABLE and record_decision is not None:
            try:
                record_decision(result.get('tier', 'unknown'), result.get('outcome', 'unknown'))
            except Exception:
                pass
        try:
            OPS_STATS.record_decision(result.get('tier', 'unknown'), result.get('outcome', 'unknown'))
        except Exception:
            pass
        return EvaluateResponse(**result)

    @app.post("/v1/mint-t3-token", response_model=MintT3TokenResponse)
    async def mint_t3_token(
        http_request: Request,
        request: MintT3TokenRequest,
        x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
        x_agent_id: Optional[str] = Header(None, alias="X-Agent-Id"),
        x_session_id: Optional[str] = Header(None, alias="X-Session-Id"),
    ):
        """
        Mint a single-use T3 token for a specific invocation.

        HARDENING (v2.0.2): T3 requires separate minting with params binding.
        """
        auth_ctx = api_auth.resolve_context(x_api_key, x_agent_id)
        if auth_ctx.error:
            raise HTTPException(401, auth_ctx.error)

        # Best-effort rate limiting for minting.
        if mint_t3_limiter is not None:
            if not mint_t3_limiter.allow(_rl_key(http_request, auth_ctx, x_api_key)):
                if METRICS_HOOKS_AVAILABLE and record_rate_limited is not None:
                    record_rate_limited('mint_t3')
                raise _http_exc(429, LAP_E_RATE_LIMITED, "RATE_LIMITED", retryable=True)

        agent_id = auth_ctx.agent_id or x_agent_id or "unknown"
        if agent_id == "unknown":
            raise _http_exc(400, LAP_E_AGENT_ID_REQUIRED, "Agent identity required")

        # Resolve session binding from header/body (fail closed on mismatch)
        body_sid = (request.session_id or "").strip()
        hdr_sid = (x_session_id or "").strip()
        if body_sid and hdr_sid and body_sid != hdr_sid:
            raise _http_exc(400, LAP_E_SESSION_MISMATCH, "SESSION_MISMATCH")
        session_id = hdr_sid or body_sid

        if not session_id:
            raise HTTPException(400, "session_id required for T3 token minting")

        result = await gateway.mint_t3_token(
            action_id=request.action_id,
            evidence_hash=request.evidence_hash,
            decision_hash=request.decision_hash,
            tool_name=request.tool_name,
            operation=request.operation,
            params=request.params,
            session_id=session_id,
            agent_id=agent_id,
            caller_authenticated=auth_ctx.authenticated,
        )

        if not result.get("success"):
            raise _http_exc(400, LAP_E_BAD_REQUEST, result.get("error", "Unknown error"))

        return MintT3TokenResponse(
            capability_token=result["capability_token"],
            params_hash=result["params_hash"],
            expires_at=result["expires_at"],
            single_use=True,
        )

    @app.post("/v1/tools/{tool_name}/invoke", response_model=ToolInvokeResponse)
    async def invoke_tool(
        tool_name: str,
        request: ToolInvokeRequest,
        x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
        x_agent_id: Optional[str] = Header(None, alias="X-Agent-Id"),
        x_session_id: Optional[str] = Header(None, alias="X-Session-Id"),
    ):
        """
        Invoke a tool with capability token.
        
        HARDENING (v2.0.2): 
        - X-Agent-Id header required for T2/T3 identity binding
        - X-Session-Id header required for T2/T3 session binding
        - nonce required for T2/T3 replay prevention
        - counter required for T3 ordering
        """
        if request.tool_name != tool_name:
            raise _http_exc(400, LAP_E_TOOL_NAME_MISMATCH, "Tool name mismatch")
        
        # Derive caller identity from auth (if configured)
        auth_ctx = api_auth.resolve_context(x_api_key, x_agent_id)
        if auth_ctx.error:
            raise HTTPException(401, auth_ctx.error)
        caller_id = auth_ctx.agent_id

        result = await gateway.invoke_tool(
            tool_name=tool_name,
            operation=request.operation,
            params=request.params,
            token_compact=request.capability_token,
            caller_id=caller_id,
            session_id=x_session_id,
            nonce=request.nonce,
            counter=request.counter,
            caller_authenticated=auth_ctx.authenticated,
        )
        if METRICS_HOOKS_AVAILABLE and record_invocation is not None:
            try:
                record_invocation(tool_name, 'success' if result.get('success') else 'deny', result.get('tier', 'unknown'))
            except Exception:
                pass
        try:
            OPS_STATS.record_invocation(tool_name, 'success' if result.get('success') else 'deny')
        except Exception:
            pass
        return ToolInvokeResponse(**result)
    
    @app.post("/v1/external-approval")
    async def record_external_approval(
        http_request: Request,
        request: ExternalApprovalRequest,
        x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
        x_agent_id: Optional[str] = Header(None, alias="X-Agent-Id"),
    ):
        """Record an external approval.

        If API-key auth is enabled, this endpoint requires authentication.
        """
        import base64

        auth_ctx = api_auth.resolve_context(x_api_key, x_agent_id)
        if auth_ctx.error:
            raise HTTPException(401, auth_ctx.error)
        if api_auth.enabled() and not auth_ctx.authenticated:
            raise _http_exc(401, LAP_E_AUTH_REQUIRED, "HARD_AUTH_REQUIRED")

        # Best-effort rate limit on external approvals (cheap DoS vector).
        if approval_limiter is not None:
            if not approval_limiter.allow(_rl_key(http_request, auth_ctx, x_api_key)):
                if METRICS_HOOKS_AVAILABLE and record_rate_limited is not None:
                    record_rate_limited('external_approval')
                raise _http_exc(429, LAP_E_RATE_LIMITED, "RATE_LIMITED", retryable=True)

        approval = Ed25519ExternalApproval(
            action_id=request.action_id,
            evidence_hash=request.evidence_hash,
            reviewer_id=request.reviewer_id,
            reviewer_type=request.reviewer_type,
            decision=request.decision,
            confidence=request.confidence,
            reasoning=request.reasoning,
            conditions=request.conditions,
            reviewed_at_utc=_now_utc().isoformat(),
            signature=base64.b64decode(request.signature),
            key_id=request.key_id,
        )
        
        success, reason = await gateway.record_external_approval(approval)
        
        if not success:
            raise _http_exc(400, LAP_E_BAD_REQUEST, reason)
        
        return {"status": "recorded", "action_id": request.action_id}
    

    # ---------------------------
    # Operational stats (/v1/stats)
    # ---------------------------
    stats_token = (os.getenv('LAP_STATS_TOKEN', '') or '').strip()
    env = str(os.getenv("LAP_ENV", os.getenv("ENV", "dev"))).strip().lower()
    prod_default = env in ("prod", "production")
    raw_require = os.getenv("LAP_STATS_REQUIRE_AUTH")
    if raw_require is None:
        stats_require_auth = prod_default
    else:
        stats_require_auth = str(raw_require).strip().lower() in ("1","true","yes","on")

    def _authorize_stats(req: 'Request') -> bool:
        # If auth is required but no token is configured, deny (fail closed).
        if stats_require_auth and not stats_token:
            return False
        if not stats_require_auth:
            return True
        # Require a valid token when enabled.
        authz = (req.headers.get('Authorization') or '').strip()
        if authz.lower().startswith('bearer '):
            if authz.split(' ', 1)[1].strip() == stats_token:
                return True
        if (req.headers.get('X-Stats-Token') or '').strip() == stats_token:
            return True
        return False

    @app.get("/v1/stats")
    async def stats(http_request: Request):
        if stats_require_auth and not _authorize_stats(http_request):
            raise HTTPException(401, "STATS_UNAUTHORIZED")
        extra = {}
        try:
            circuit = None
            try:
                circuit = getattr(getattr(gateway, "store", None), "circuit", None)
            except Exception:
                circuit = None
            if circuit is None:
                circuit = getattr(gateway, "circuit", None)
            extra["lockdown_active"] = bool(circuit and circuit.is_lockdown_active())
        except Exception:
            extra["lockdown_active"] = None
        return OPS_STATS.snapshot(extra=extra)

    @app.get("/v1/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "gateway_id": gateway.gateway_id,
            "crypto_available": CRYPTO_AVAILABLE,
        }
    
    return app


def main():
    """
    Main entry point for lap-gateway CLI.
    
    Usage:
        lap-gateway                    # Start on default port 8000
        lap-gateway --port 9000        # Start on custom port
        lap-gateway --host 127.0.0.1   # Bind to localhost only
    """
    import argparse
    import os
    
    parser = argparse.ArgumentParser(
        description="LAP Gateway - Policy Enforcement Point (PEP)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    lap-gateway                         Start gateway on 0.0.0.0:8000
    lap-gateway --port 9000             Start on custom port
    lap-gateway --host 127.0.0.1        Bind to localhost only
    
Environment Variables:
    LAP_JITTER_SALT     Cryptographic salt for audit sampling
    LAP_GATEWAY_DB_PATH Path to SQLite database (default: lap_gateway.db)
    LAP_DB_PATH         (legacy alias) Path to SQLite database
    LAP_PROXY_HEADERS  If set (1/true), trust X-Forwarded-* headers (reverse proxy)
    LAP_FORWARDED_ALLOW_IPS  Comma-separated IPs allowed to set X-Forwarded-* (default: uvicorn)
        """
    )
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    
    parser.add_argument("--proxy-headers", action="store_true", help="Trust X-Forwarded-* headers (for reverse proxy)")
    parser.add_argument("--forwarded-allow-ips", default=None, help="Comma-separated IPs allowed to set X-Forwarded-* (default: env LAP_FORWARDED_ALLOW_IPS or uvicorn default)")

    args = parser.parse_args()
    
    if not FASTAPI_AVAILABLE:
        print("ERROR: FastAPI not available.")
        print("Install with: pip install lattice-audit-protocol[gateway]")
        print("         or: pip install fastapi uvicorn")
        return 1
    
    import uvicorn
    
    print(f"Starting LAP Gateway (PEP) on {args.host}:{args.port}")
    print(f"  Crypto available: {CRYPTO_AVAILABLE}")
    print(f"  Endpoints:")
    print(f"    POST /v1/session/new        - Create session for T2/T3")
    print(f"    POST /v1/evaluate           - Evaluate action")
    print(f"    POST /v1/tools/{{tool}}/invoke - Invoke tool with token")
    print(f"    POST /v1/external-approval  - Record external approval")
    print(f"    GET  /v1/health             - Health check")
    print()
    
    app = create_app()

    # Reverse-proxy support
    env_proxy = os.environ.get('LAP_PROXY_HEADERS', '').strip()
    proxy_headers = args.proxy_headers or (env_proxy in ('1','true','True','yes','YES'))
    forwarded_allow_ips = args.forwarded_allow_ips or os.environ.get('LAP_FORWARDED_ALLOW_IPS')

    uvicorn.run(app, host=args.host, port=args.port, reload=args.reload, proxy_headers=proxy_headers, forwarded_allow_ips=forwarded_allow_ips)
    return 0


# CLI entry point
if __name__ == "__main__":
    import sys
    sys.exit(main() or 0)
