"""
Lattice Audit Protocol - Reference Implementation (v1.7)
========================================================

A governance layer for advanced AI systems operating under:
- Structural counterfactual uncertainty ("God-Lock") as a continuum, not a binary
- Semantic drift ("philosoplasticity") in operational meanings over time

This is a *reference* implementation designed to be:
- Explicit about policy dials and value-loading at design-time
- Auditable (hash-chained logs, persistence)
- Concurrency-safe (threading locks)
- Empirically testable (hooks + benchmark-facing interfaces)

Author: Dave Gallop (PPGigantus)
Maintainer notes: This implementation is intentionally conservative and "default-deny"
for high-irreversibility actions unless sufficient warrant is demonstrated.

License: MIT (recommended) or CC0 for spec/code split

Version: 1.7
Date: January 2026
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Protocol, Callable, ClassVar
import datetime
import hashlib
import json
import logging
import math
import os
import sqlite3
import threading

# ---------------------------
# Logging Configuration
# ---------------------------

logger = logging.getLogger("lattice_audit")
logger.setLevel(logging.DEBUG)

# Default handler (can be overridden by users)
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ"
    ))
    logger.addHandler(_handler)


# ---------------------------
# Enums / Core Types
# ---------------------------

class ActionTier(Enum):
    """Action classification by irreversibility and risk."""
    T0_ROUTINE = 0      # irr < 0.10, minimal harm potential
    T1_SENSITIVE = 1    # 0.10 ≤ irr < 0.30
    T2_HIGH_STAKES = 2  # 0.30 ≤ irr < 0.70
    T3_CATASTROPHIC = 3 # irr ≥ 0.70 OR catastrophic threshold crossed OR externalized irreversible harm

class AuditOutcome(Enum):
    APPROVE = "approve"
    DENY = "deny"
    ESCROW = "escrow"            # delay/contain pending reevaluation
    REQUIRE_EXTERNAL_REVIEW = "require_external_review"

class AuditorRole(Enum):
    """Explicit roles. Diversity comes from *role + inductive bias*, not seed-level randomness."""
    PRIMARY_DECIDER = "primary_decider"
    SAFETY_CRITIC = "safety_critic"
    IRREVERSIBILITY_AUDITOR = "irreversibility_auditor"
    NOVELTY_AUDITOR = "novelty_auditor"
    SUFFERING_AUDITOR = "suffering_auditor"
    DEVILS_ADVOCATE = "devils_advocate"  # REQUIRED for T2/T3: must always produce objection
    ENTRY_GATE = "entry_gate"  # Independent tier estimation before main evaluation

class ObjectionSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

# ---------------------------
# Utility helpers
# ---------------------------

# HARDENING (v1.9.0): Epsilon for float comparisons
# Prevents "edge case flips" where threshold comparisons differ across hardware
FLOAT_EPSILON = 1e-9

def _float_ge(a: float, b: float, epsilon: float = FLOAT_EPSILON) -> bool:
    """Safe greater-than-or-equal comparison for floats."""
    return a > b - epsilon

def _float_gt(a: float, b: float, epsilon: float = FLOAT_EPSILON) -> bool:
    """Safe greater-than comparison for floats."""
    return a > b + epsilon

def _float_le(a: float, b: float, epsilon: float = FLOAT_EPSILON) -> bool:
    """Safe less-than-or-equal comparison for floats."""
    return a < b + epsilon

def _float_lt(a: float, b: float, epsilon: float = FLOAT_EPSILON) -> bool:
    """Safe less-than comparison for floats."""
    return a < b - epsilon

def _now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)

def _get_jitter_salt(policy_salt: Optional[str] = None) -> Optional[str]:
    """
    Get jitter salt from environment variable or policy.
    
    HARDENING (v1.7.9): Salt should come from environment variable LAP_JITTER_SALT
    rather than config files that agents might read.
    
    Priority:
    1. Environment variable LAP_JITTER_SALT
    2. Policy-provided salt (jitter_server_salt)
    3. None (vulnerable - will warn)
    """
    env_salt = os.environ.get("LAP_JITTER_SALT")
    if env_salt:
        return env_salt
    if policy_salt:
        logger.warning(
            "Using jitter salt from policy config instead of environment variable. "
            "For production, set LAP_JITTER_SALT environment variable to prevent "
            "agents from reading the salt from config files."
        )
        return policy_salt
    return None

def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _safe_hash_encode(components: List[str]) -> bytes:
    """
    Create an unambiguous byte encoding for hash chain components.
    
    HARDENING (v1.8.0): Uses length-prefixed encoding to prevent collision attacks
    where attacker-controlled fields containing "||" could create ambiguous encodings.
    
    Format: for each component, encode as: 
        <8-byte big-endian length><UTF-8 bytes>
    
    This ensures different component tuples always produce different byte sequences,
    even if individual components contain the delimiter characters.
    """
    result = b""
    for component in components:
        encoded = component.encode("utf-8")
        # Use 8-byte length prefix (big-endian) to handle very large fields
        length_bytes = len(encoded).to_bytes(8, byteorder="big")
        result += length_bytes + encoded
    return result

def _legacy_hash_encode(components: List[str]) -> bytes:
    """
    Legacy "||" delimiter encoding for backward compatibility.
    
    WARNING: This encoding is vulnerable to collision attacks if attacker-controlled
    fields contain "||". Only use for verifying records from v1.7.x.
    """
    return "||".join(components).encode("utf-8")

def _normalize_floats(obj: Any, precision: int = 8, fail_on_special: bool = True) -> Any:
    """
    Recursively normalize floats to fixed precision for deterministic hashing.
    This prevents hash chain breaks due to floating-point representation differences
    across different hardware/interpreters.
    
    HARDENING (v1.7.4):
    - Uses 8 decimal places for cross-platform determinism
    - NaN/Inf are encoded as tagged objects {"__special_float__": "nan"} to prevent
      collision with legitimate strings "NaN" or "Inf"
    - If fail_on_special=True (default), raises ValueError on NaN/Inf for strict validation
    
    Args:
        obj: Object to normalize
        precision: Decimal places for rounding (default 8)
        fail_on_special: If True, raise on NaN/Inf instead of encoding
        
    Raises:
        ValueError: If fail_on_special=True and NaN/Inf encountered
    """
    if isinstance(obj, float):
        if math.isnan(obj):
            if fail_on_special:
                raise ValueError("NaN values are not allowed in canonical JSON (potential hash collision)")
            return {"__special_float__": "nan"}
        if math.isinf(obj):
            if fail_on_special:
                raise ValueError("Inf values are not allowed in canonical JSON (potential hash collision)")
            return {"__special_float__": "inf" if obj > 0 else "-inf"}
        # Round to fixed precision to ensure cross-platform determinism
        return round(obj, precision)
    elif isinstance(obj, dict):
        return {k: _normalize_floats(v, precision, fail_on_special) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [_normalize_floats(v, precision, fail_on_special) for v in obj]
    return obj


def _canonical_json(obj: Any, strict: bool = True) -> str:
    """
    Deterministic JSON for hashing/audit.
    
    HARDENING (v1.7.4):
    - Float normalization to 8 decimal places
    - NaN/Inf are REJECTED by default (strict=True) to prevent type collisions
    - Stable key sorting
    - No ensure_ascii for consistent Unicode handling
    
    Args:
        obj: Object to serialize
        strict: If True (default), raise on NaN/Inf. If False, encode as tagged objects.
        
    Raises:
        ValueError: If strict=True and NaN/Inf values are present
    """
    try:
        normalized = _normalize_floats(obj, fail_on_special=strict)
        return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except ValueError as e:
        raise ValueError(f"Cannot create canonical JSON: {e}") from e


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))

# ---------------------------
# Evidence primitives
# ---------------------------

@dataclass(frozen=True)
class UncertaintyBand:
    """
    A bounded uncertainty interval for an outcome delta (e.g., expected net benefit).
    Units are domain-specific, but must be consistent across evidence and alternatives.
    """
    lower: float
    upper: float
    confidence_level: float  # confidence that true value lies within [lower, upper], in [0,1]

    def validate(self) -> List[str]:
        """
        Validate the uncertainty band.
        
        HARDENING (v1.7.6): Checks for NaN/Inf which would corrupt comparisons.
        """
        errors: List[str] = []
        # Check for NaN/Inf first - comparisons with NaN always return False
        if not math.isfinite(self.lower):
            errors.append(f"UncertaintyBand: lower must be finite, got {self.lower}")
        if not math.isfinite(self.upper):
            errors.append(f"UncertaintyBand: upper must be finite, got {self.upper}")
        if not math.isfinite(self.confidence_level):
            errors.append(f"UncertaintyBand: confidence_level must be finite, got {self.confidence_level}")
        # Only do range checks if values are finite
        if math.isfinite(self.lower) and math.isfinite(self.upper) and self.lower > self.upper:
            errors.append(f"UncertaintyBand: lower ({self.lower}) > upper ({self.upper})")
        if math.isfinite(self.confidence_level) and not (0.0 <= self.confidence_level <= 1.0):
            errors.append(f"UncertaintyBand: confidence_level must be in [0,1], got {self.confidence_level}")
        return errors

    def width(self) -> float:
        return self.upper - self.lower

    def crosses_zero(self) -> bool:
        return self.lower <= 0.0 <= self.upper


@dataclass(frozen=True)
class IrreversibilityFactors:
    """
    Factors are scored as *reversibility* in [0,1] (1 = fully reversible, 0 = irreversible).

    These factors are intentionally separated to force explicit thinking about:
    - temporal reversibility: can we undo quickly before effects propagate?
    - informational reversibility: can we "unlearn" / retract knowledge exposure?
    - causal reversibility: can downstream consequences be reversed in the environment?
    """
    temporal_reversibility: float
    informational_reversibility: float
    causal_reversibility: float

    def validate(self) -> List[str]:
        """
        Validate the irreversibility factors.
        
        HARDENING (v1.7.6): Explicit NaN/Inf checks with clear error messages.
        """
        errors: List[str] = []
        for name, v in [
            ("temporal_reversibility", self.temporal_reversibility),
            ("informational_reversibility", self.informational_reversibility),
            ("causal_reversibility", self.causal_reversibility),
        ]:
            if not math.isfinite(v):
                errors.append(f"IrreversibilityFactors: {name} must be finite, got {v}")
            elif not (0.0 <= v <= 1.0):
                errors.append(f"IrreversibilityFactors: {name} must be in [0,1], got {v}")
        return errors


@dataclass(frozen=True)
class IrreversibilityAssessment:
    """
    A concrete assessment used to compute irreversibility.
    This acknowledges the regress: measuring irreversibility requires judgment.
    We make that judgment explicit, attributable, and confidence-scored.
    
    HARDENING (v1.7.5):
    - temporal_horizon_years: Explicit time horizon for reversibility assessment
    - long_term_irreversibility: Separate score for effects that emerge over time
    
    This addresses the "Heuristic Foundation Gap" where actions appear reversible
    short-term but become functionally irreversible long-term.
    """
    factors: IrreversibilityFactors
    method: str  # e.g., "rubric_v1", "causal_graph", "info_theory_proxy"
    notes: str
    reversibility_plan: str  # rollback/containment plan (may be empty for low-stakes)
    assessor: str  # e.g., "actor", "auditor:irreversibility_auditor", "human_panel"
    confidence: float  # confidence in the factors being approximately correct (NOT that action is justified)
    
    # TEMPORAL HORIZON (Heuristic Foundation Gap mitigation)
    temporal_horizon_years: float = 1.0  # Time horizon over which reversibility was assessed
    long_term_irreversibility: float = 0.0  # [0,1] Score for effects emerging beyond horizon
    long_term_assessment_method: str = "none"  # How long-term effects were assessed

    def validate(self) -> List[str]:
        errors = self.factors.validate()
        if not self.method or len(self.method) > 80:
            errors.append("IrreversibilityAssessment: method must be a short non-empty identifier")
        if not (0.0 <= self.confidence <= 1.0):
            errors.append(f"IrreversibilityAssessment: confidence must be in [0,1], got {self.confidence}")
        if not self.assessor:
            errors.append("IrreversibilityAssessment: assessor must be non-empty")
        # TEMPORAL HORIZON VALIDATION
        if self.temporal_horizon_years <= 0:
            errors.append(f"IrreversibilityAssessment: temporal_horizon_years must be > 0, got {self.temporal_horizon_years}")
        if not (0.0 <= self.long_term_irreversibility <= 1.0):
            errors.append(f"IrreversibilityAssessment: long_term_irreversibility must be in [0,1], got {self.long_term_irreversibility}")
        return errors
    
    def effective_irreversibility(self) -> float:
        """
        Compute effective irreversibility considering both short and long-term effects.
        
        If long_term_irreversibility is higher than factors-based score, use the maximum.
        This prevents gaming by only assessing short-term reversibility.
        """
        short_term = 1.0 - (
            self.factors.temporal_reversibility *
            self.factors.informational_reversibility *
            self.factors.causal_reversibility
        ) ** (1/3)
        return max(short_term, self.long_term_irreversibility)


# ---------------------------
# Evidence Attestation (Oracle Problem Mitigation)
# ---------------------------

class AttestationMethod(Enum):
    """
    Methods for external verification of evidence.
    
    This addresses the "Oracle Problem" - the system relies on EvidenceObject
    being provided, but a sophisticated agent might fabricate evidence.
    
    Attestation provides hooks for external verification systems.
    """
    NONE = "none"                    # No external attestation (default)
    SIGNATURE = "signature"          # Cryptographic signature from trusted party
    ZK_PROOF = "zk_proof"           # Zero-knowledge proof of evidence validity
    ORACLE = "oracle"               # External oracle verification
    MPC = "mpc"                     # Multi-party computation result
    DAO_VOTE = "dao_vote"           # Decentralized governance attestation
    CROSS_AGENT = "cross_agent"     # Verified by multiple independent agents


@dataclass(frozen=True)
class EvidenceAttestation:
    """
    External attestation of evidence validity.
    
    This is an integration point for decentralized verification systems
    (ZK proofs, oracles, MPC, DAO votes, etc.) to vouch for evidence integrity.
    
    The LAP system itself doesn't verify these - it records them for downstream
    systems and human auditors to inspect.
    """
    method: AttestationMethod
    attestor_id: str                 # Who/what attested (public key, oracle ID, DAO address)
    signature: str                   # Cryptographic signature or proof hash
    timestamp_utc: str               # When attestation was made
    
    # Optional metadata for different attestation types
    verification_endpoint: str = ""  # URL/address for external verification
    attestation_chain: str = ""      # For blockchain-based attestations
    confidence: float = 1.0          # Attestor's confidence in evidence validity [0,1]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def validate(self) -> List[str]:
        errors: List[str] = []
        if not self.attestor_id:
            errors.append("EvidenceAttestation: attestor_id must be non-empty")
        if not self.signature:
            errors.append("EvidenceAttestation: signature must be non-empty")
        try:
            datetime.datetime.fromisoformat(self.timestamp_utc.replace("Z", "+00:00"))
        except Exception:
            errors.append(f"EvidenceAttestation: timestamp_utc must be ISO8601, got {self.timestamp_utc}")
        if not (0.0 <= self.confidence <= 1.0):
            errors.append(f"EvidenceAttestation: confidence must be in [0,1], got {self.confidence}")
        return errors
    
    def is_strong(self) -> bool:
        """Returns True if this is a strong attestation method."""
        return self.method in (
            AttestationMethod.ZK_PROOF,
            AttestationMethod.MPC,
            AttestationMethod.DAO_VOTE,
        )


@dataclass(frozen=True)
class AlternativeOption:
    """
    An evaluated alternative action.
    
    HARDENING (v1.7.5):
    - semantic_embedding: Optional embedding vector for semantic similarity checks
    - causal_strategy: Required categorization of the alternative's approach
    - embedding_model_id: Identifies the model used for embedding (for comparability)
    
    HARDENING (v1.7.8):
    - Strategy-content validation ensures description matches claimed strategy
    
    This addresses the "Gaming Straw-Man Detection" problem where token-diverse
    alternatives could still be semantically similar to the main action.
    """
    description: str
    expected_utility: UncertaintyBand
    irreversibility: IrreversibilityAssessment
    estimated_compute_cost: float = 1.0  # relative units; 1.0 ~ baseline action
    tags: List[str] = field(default_factory=list)
    
    # SEMANTIC EMBEDDING (Straw-Man Detection hardening)
    # If provided, used for semantic similarity comparison with main action
    semantic_embedding: Optional[List[float]] = None
    embedding_model_id: str = "none"  # e.g., "openai-text-embedding-3-small"
    
    # CAUSAL STRATEGY (prevents token-diverse but strategically-similar alternatives)
    # Must be one of: "negotiate", "delay", "partial", "delegate", "substitute", 
    #                 "mitigate", "monitor", "abstain", "other"
    causal_strategy: str = "other"
    
    # OPTIMALITY COMPARISON (prevents "sincere-looking" but subtly inferior alternatives)
    # If True, this alternative has been independently verified as viable
    independently_verified: bool = False
    verification_method: str = "none"  # e.g., "expert_review", "simulation", "formal_proof"
    
    # Strategy-to-keywords mapping for content validation (v1.7.8)
    STRATEGY_KEYWORDS: ClassVar[Dict[str, List[str]]] = {
        "negotiate": ["negotiate", "discuss", "dialogue", "agreement", "compromise", 
                     "stakeholder", "consensus", "mediate", "arbitrate", "talk"],
        "delay": ["delay", "postpone", "wait", "defer", "pause", "hold", "suspend",
                 "later", "reschedule", "extend", "timeline"],
        "partial": ["partial", "incremental", "phased", "gradual", "subset", "portion",
                   "limited", "step", "stage", "pilot", "rollout"],
        "delegate": ["delegate", "assign", "hand off", "transfer", "outsource",
                    "authorize", "empower", "entrust", "refer", "escalate"],
        "substitute": ["substitute", "replace", "alternative", "swap", "exchange",
                      "instead", "rather", "different", "other option", "switch"],
        "mitigate": ["mitigate", "reduce", "minimize", "safeguard", "protect",
                    "hedge", "buffer", "backup", "fallback", "insurance"],
        "monitor": ["monitor", "observe", "watch", "track", "measure", "assess",
                   "evaluate", "review", "audit", "check", "inspect"],
        "abstain": ["abstain", "refrain", "avoid", "not proceed", "decline",
                   "reject", "stop", "cancel", "abort", "withdraw"],
    }

    def validate(self) -> List[str]:
        """
        Validate the alternative option.
        
        HARDENING (v1.7.6): Checks for NaN/Inf in numeric fields including embeddings.
        """
        errors: List[str] = []
        if not self.description or len(self.description) < 8:
            errors.append("AlternativeOption: description must be descriptive (>=8 chars)")
        errors.extend(self.expected_utility.validate())
        errors.extend(self.irreversibility.validate())
        # Check estimated_compute_cost for NaN/Inf
        if not math.isfinite(self.estimated_compute_cost):
            errors.append(f"AlternativeOption: estimated_compute_cost must be finite, got {self.estimated_compute_cost}")
        elif self.estimated_compute_cost <= 0:
            errors.append("AlternativeOption: estimated_compute_cost must be > 0")
        # Validate causal strategy
        valid_strategies = {"negotiate", "delay", "partial", "delegate", "substitute", 
                          "mitigate", "monitor", "abstain", "other"}
        if self.causal_strategy not in valid_strategies:
            errors.append(f"AlternativeOption: causal_strategy must be one of {valid_strategies}, got '{self.causal_strategy}'")
        # Validate embedding if provided
        if self.semantic_embedding is not None:
            if len(self.semantic_embedding) < 10:
                errors.append("AlternativeOption: semantic_embedding must have at least 10 dimensions")
            if self.embedding_model_id == "none":
                errors.append("AlternativeOption: embedding_model_id required when semantic_embedding is provided")
            # HARDENING: Check for NaN/Inf in embedding values
            for i, v in enumerate(self.semantic_embedding):
                if not math.isfinite(v):
                    errors.append(f"AlternativeOption: semantic_embedding[{i}] must be finite, got {v}")
                    break  # Don't spam errors for every NaN
        return errors
    
    def validate_strategy_content(self, min_keyword_matches: int = 1) -> Tuple[bool, Optional[str]]:
        """
        Validate that the description content matches the claimed causal_strategy.
        
        HARDENING (v1.7.8): Prevents straw-man strategy tagging where an agent
        claims a strategy (e.g., "mitigate") but the description doesn't actually
        describe that strategy.
        
        HARDENING (v1.7.9): Detects "Semantic Hijacking" where harmful keywords
        appear alongside strategy keywords (e.g., "deploy virus then observe").
        
        Args:
            min_keyword_matches: Minimum number of strategy keywords that must appear
            
        Returns:
            (is_valid, reason): True if strategy matches content
        """
        # "other" strategy doesn't require keyword validation
        if self.causal_strategy == "other":
            return (True, None)
        
        keywords = self.STRATEGY_KEYWORDS.get(self.causal_strategy, [])
        if not keywords:
            return (True, None)  # Unknown strategy, skip validation
        
        desc_lower = self.description.lower()
        
        # HARDENING (v1.7.9): Check for harmful/contradictory keywords that suggest hijacking
        # If description contains harmful action words, the strategy keyword might be a decoy
        HARMFUL_KEYWORDS = {
            "deploy", "execute", "launch", "attack", "destroy", "delete", "remove",
            "virus", "malware", "exploit", "hack", "breach", "override", "bypass",
            "kill", "terminate", "eliminate", "eradicate", "shutdown", "crash",
            "inject", "infect", "corrupt", "damage", "harm", "hurt", "disable"
        }
        
        # Find harmful keywords in description
        harmful_found = [kw for kw in HARMFUL_KEYWORDS if kw in desc_lower]
        
        # Find strategy keywords in description
        strategy_found = [kw for kw in keywords if kw in desc_lower]
        
        # If harmful keywords found, check if they're the PRIMARY action
        if harmful_found and strategy_found:
            # Check keyword positions - strategy should come FIRST
            first_harmful_pos = min(desc_lower.find(kw) for kw in harmful_found if kw in desc_lower)
            first_strategy_pos = min(desc_lower.find(kw) for kw in strategy_found if kw in desc_lower)
            
            if first_harmful_pos < first_strategy_pos:
                return (False,
                    f"SEMANTIC_HIJACKING_DETECTED: Description contains harmful action keywords "
                    f"{harmful_found} BEFORE strategy keywords {strategy_found}. "
                    f"Strategy '{self.causal_strategy}' appears to be a decoy. "
                    f"The primary action seems to be '{harmful_found[0]}', not '{self.causal_strategy}'."
                )
            
            # Also check for "and then" / "afterwards" patterns that suggest strategy is secondary
            hijack_patterns = ["and then", "afterwards", "after that", "finally", "then"]
            for pattern in hijack_patterns:
                if pattern in desc_lower:
                    pattern_pos = desc_lower.find(pattern)
                    # If any strategy keyword appears AFTER the pattern, it might be a decoy
                    for strat_kw in strategy_found:
                        kw_pos = desc_lower.find(strat_kw)
                        if kw_pos > pattern_pos:
                            return (False,
                                f"SEMANTIC_HIJACKING_DETECTED: Strategy keyword '{strat_kw}' appears "
                                f"after '{pattern}' pattern, suggesting it's a secondary/decoy action. "
                                f"Harmful keywords {harmful_found} appear to be the primary action."
                            )
        
        matches = len(strategy_found)
        
        if matches < min_keyword_matches:
            return (False, 
                f"Strategy '{self.causal_strategy}' claims but description lacks expected keywords. "
                f"Found {matches}/{min_keyword_matches} required matches. "
                f"Expected keywords like: {', '.join(keywords[:5])}..."
            )
        
        return (True, None)

    def fingerprint(self) -> str:
        # Normalize description for duplicate detection
        d = " ".join(self.description.lower().split())
        return _sha256_hex(d.encode("utf-8"))
    
    def semantic_distance(self, other: "AlternativeOption") -> Optional[float]:
        """
        Compute semantic distance to another alternative using embeddings.
        
        Returns cosine distance [0, 2] where 0 = identical, 2 = opposite.
        Returns None if embeddings are not available or incompatible.
        """
        if self.semantic_embedding is None or other.semantic_embedding is None:
            return None
        if self.embedding_model_id != other.embedding_model_id:
            return None  # Incompatible embeddings
        if len(self.semantic_embedding) != len(other.semantic_embedding):
            return None
        
        # Cosine distance
        dot = sum(a * b for a, b in zip(self.semantic_embedding, other.semantic_embedding))
        norm_self = sum(a * a for a in self.semantic_embedding) ** 0.5
        norm_other = sum(b * b for b in other.semantic_embedding) ** 0.5
        
        if norm_self < 1e-10 or norm_other < 1e-10:
            return None  # Zero vectors
        
        cosine_sim = dot / (norm_self * norm_other)
        return 1.0 - cosine_sim  # Distance = 1 - similarity


@dataclass(frozen=True)
class EvidenceObject:
    """
    The core audit evidence.

    IMPORTANT: This object is designed to be hash-bound and persisted.
    Do not add non-deterministic fields without excluding them from hashing.
    """
    action_id: str
    description: str
    timestamp_utc: str

    # Measurement pillars
    irreversibility: IrreversibilityAssessment
    outcome_delta: UncertaintyBand

    # "Sufficient warrant under bounded rationality" (a policy dial)
    necessity_confidence: float  # [0,1] confidence that the action is necessary vs. viable alternatives

    # Novelty / diversity impact (domain-defined proxy, but must be stated)
    novelty_loss_estimate: float  # [0,1], higher = more novelty destroyed/foreclosed
    novelty_method: str           # short identifier (e.g., "agent_diversity_proxy")

    # Catastrophic suffering proxy (domain-defined, but must be stated)
    suffering_risk_estimate: float # [0,1], higher = greater plausible catastrophic suffering
    suffering_method: str          # short identifier (e.g., "phase_space_compression_proxy")

    # Alternatives for reversibility preference checks
    alternatives: List[AlternativeOption] = field(default_factory=list)

    # Optional narrative fields
    counterfactual_gap_statement: str = ""
    provenance: Dict[str, Any] = field(default_factory=dict)
    
    # External attestations (Oracle Problem mitigation)
    # Multiple attestations can be provided for defense-in-depth
    attestations: List[EvidenceAttestation] = field(default_factory=list)
    
    # IRREPLACEABLE NOVELTY NODES (INNs) Assessment
    # Required for T2/T3 actions that may impact unique/irreplaceable entities
    inn_impact_assessment: str = ""  # Description of impact on INNs
    inn_affected_count: int = 0      # Estimated number of INNs affected
    inn_substitutability: float = 1.0  # [0,1] 0=no substitute possible, 1=easily substitutable
    
    # Alternative quality metadata (for straw-man detection)
    alternative_strategy_tags: List[str] = field(default_factory=list)  # e.g., ["negotiate", "delay", "partial"]

    def validate(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        if not self.action_id:
            errors.append("EvidenceObject: action_id must be non-empty")
        if not self.description or len(self.description) < 8:
            errors.append("EvidenceObject: description must be descriptive (>=8 chars)")
        # timestamp sanity
        try:
            datetime.datetime.fromisoformat(self.timestamp_utc.replace("Z","+00:00"))
        except Exception:
            errors.append("EvidenceObject: timestamp_utc must be ISO format (e.g., 2026-01-05T00:00:00Z)")

        errors.extend(self.irreversibility.validate())
        errors.extend(self.outcome_delta.validate())

        if not (0.0 <= self.necessity_confidence <= 1.0):
            errors.append("EvidenceObject: necessity_confidence must be in [0,1]")

        for name, v in [
            ("novelty_loss_estimate", self.novelty_loss_estimate),
            ("suffering_risk_estimate", self.suffering_risk_estimate),
        ]:
            if not (0.0 <= v <= 1.0):
                errors.append(f"EvidenceObject: {name} must be in [0,1], got {v}")

        if not self.novelty_method or len(self.novelty_method) > 80:
            errors.append("EvidenceObject: novelty_method must be a short non-empty identifier")
        if not self.suffering_method or len(self.suffering_method) > 80:
            errors.append("EvidenceObject: suffering_method must be a short non-empty identifier")
        
        # INN validation
        if not (0.0 <= self.inn_substitutability <= 1.0):
            errors.append("EvidenceObject: inn_substitutability must be in [0,1]")
        if self.inn_affected_count < 0:
            errors.append("EvidenceObject: inn_affected_count cannot be negative")
        
        # INN FLOOR INVARIANT ENFORCEMENT (v1.7.6)
        # These are HARD limits that cannot be bypassed
        INN_ABSOLUTE_MINIMUM_FLOOR = 0.25  # Structural invariant
        INN_MAX_SUBSTITUTABILITY_CAP = 0.90  # Cannot claim >90% substitutability
        
        # If action affects INNs, enforce substitutability cap
        if self.inn_affected_count > 0:
            if self.inn_substitutability > INN_MAX_SUBSTITUTABILITY_CAP:
                errors.append(
                    f"EvidenceObject: INN_SUBSTITUTABILITY_VIOLATION - inn_substitutability ({self.inn_substitutability:.2f}) "
                    f"exceeds cap ({INN_MAX_SUBSTITUTABILITY_CAP}) for INN-affecting actions. "
                    "This is a structural invariant that cannot be bypassed."
                )
        
        # Novelty floor enforcement
        if self.novelty_loss_estimate < INN_ABSOLUTE_MINIMUM_FLOOR:
            # This is OK - novelty can be low for non-INN-affecting actions
            pass
        
        # If claiming low novelty for INN-affecting action, this is suspicious
        if self.inn_affected_count > 0 and self.novelty_loss_estimate < 0.3:
            # Warning-level check - logged but not an error
            # The actual enforcement happens in the auditors
            pass

        # Alternatives: cross-field logic
        seen = set()
        for alt in self.alternatives:
            errors.extend(alt.validate())
            fp = alt.fingerprint()
            if fp in seen:
                errors.append("EvidenceObject: alternatives contain duplicates/near-duplicates")
            seen.add(fp)
        
        # ALTERNATIVE QUALITY CHECKS (Straw-man detection)
        # Calculate inferred tier for context
        agent_irr = 1.0 - (
            self.irreversibility.factors.temporal_reversibility *
            self.irreversibility.factors.informational_reversibility *
            self.irreversibility.factors.causal_reversibility
        ) ** (1/3)
        is_high_tier = agent_irr >= 0.30 or self.suffering_risk_estimate >= 0.30
        
        if is_high_tier:
            # T2/T3 require minimum alternatives
            if agent_irr >= 0.70 or self.suffering_risk_estimate >= 0.70:
                # T3: Require at least 2 distinct alternatives
                if len(self.alternatives) < 2:
                    errors.append("EvidenceObject: T3 actions require at least 2 evaluated alternatives")
            else:
                # T2: Require at least 1 alternative
                if len(self.alternatives) < 1:
                    errors.append("EvidenceObject: T2 actions require at least 1 evaluated alternative")
            
            # Check for straw-man alternatives (high semantic similarity)
            if len(self.alternatives) >= 1:
                main_tokens = set(self.description.lower().split())
                straw_men = []
                for alt in self.alternatives:
                    alt_tokens = set(alt.description.lower().split())
                    if len(main_tokens | alt_tokens) > 0:
                        overlap = len(main_tokens & alt_tokens) / len(main_tokens | alt_tokens)
                        if overlap > 0.70:
                            straw_men.append(alt.description[:30])
                
                if straw_men and len(straw_men) == len(self.alternatives):
                    errors.append(
                        f"EvidenceObject: INSINCERE_ALTERNATIVES - all alternatives have >70% token overlap "
                        f"with main action. Provide meaningfully distinct alternatives."
                    )
            
            # HARDENING (v1.7.7): STRATEGY DIVERSITY CHECK
            # Prevents "Deploy blue/red/green button" type straw-man alternatives
            # that have different descriptions but identical causal_strategy
            if len(self.alternatives) >= 2:
                strategies = [alt.causal_strategy for alt in self.alternatives]
                unique_strategies = set(strategies)
                
                # Require at least 2 different strategies for T2/T3
                if len(unique_strategies) == 1 and unique_strategies != {"other"}:
                    errors.append(
                        f"EvidenceObject: STRATEGY_MONOCULTURE - all {len(self.alternatives)} alternatives "
                        f"share the same causal_strategy='{strategies[0]}'. "
                        f"T2/T3 actions require alternatives with different strategic approaches "
                        f"(e.g., negotiate, delay, partial, delegate, substitute, mitigate, monitor, abstain)."
                    )
                
                # For T3, require at least 2 distinct non-"other" strategies
                if agent_irr >= 0.70 or self.suffering_risk_estimate >= 0.70:
                    non_other_strategies = {s for s in unique_strategies if s != "other"}
                    if len(non_other_strategies) < 2 and len(self.alternatives) >= 2:
                        errors.append(
                            f"EvidenceObject: T3_STRATEGY_DIVERSITY - T3 actions require at least 2 distinct "
                            f"causal strategies (not 'other'). Found: {unique_strategies}. "
                            f"Use specific strategies like: negotiate, delay, partial, delegate, substitute, "
                            f"mitigate, monitor, abstain."
                        )
            
            # HARDENING (v1.7.8): STRATEGY-CONTENT VALIDATION
            # Ensures the description content actually matches the claimed strategy tag
            # Prevents straw-man tagging where content is identical but tags differ
            for i, alt in enumerate(self.alternatives):
                is_valid, reason = alt.validate_strategy_content(min_keyword_matches=1)
                if not is_valid:
                    errors.append(
                        f"EvidenceObject: STRATEGY_CONTENT_MISMATCH (alternative[{i}]): {reason}"
                    )
            
            # Check for catastrophic baseline alternatives (e.g., "do nothing and crash")
            for alt in self.alternatives:
                alt_mid = 0.5 * (alt.expected_utility.lower + alt.expected_utility.upper)
                if alt_mid < -0.5:  # Clearly catastrophic outcome
                    if "nothing" in alt.description.lower() or "crash" in alt.description.lower():
                        errors.append(
                            f"EvidenceObject: STRAW_ALTERNATIVE - '{alt.description[:30]}...' "
                            f"appears to be a catastrophic baseline. Provide realistic alternatives."
                        )
            
            # INN assessment required for high-tier actions with novelty impact
            if self.novelty_loss_estimate > 0.3 and not self.inn_impact_assessment:
                errors.append(
                    "EvidenceObject: T2/T3 actions with novelty_loss > 0.3 require inn_impact_assessment"
                )

        # HARD CHECK: Necessity Inflation Detection
        # If claiming high necessity but alternatives are numerous and comparable/better, this is
        # a potential "safety-washing" attempt and MUST be rejected as a validation error.
        # This closes the "necessity inflation loophole" identified in God-Lock analysis.
        if self.necessity_confidence > 0.8 and len(self.alternatives) >= 2:
            action_mid = 0.5 * (self.outcome_delta.lower + self.outcome_delta.upper)
            comparable_alts = []
            for alt in self.alternatives:
                alt_mid = 0.5 * (alt.expected_utility.lower + alt.expected_utility.upper)
                # Alternative is comparable if within 20% of action utility OR better
                if alt_mid >= action_mid * 0.8:
                    comparable_alts.append(alt.description[:30])
            
            if len(comparable_alts) >= 2:
                errors.append(
                    f"EvidenceObject: NECESSITY INFLATION DETECTED - necessity_confidence={self.necessity_confidence:.2f} "
                    f"but {len(comparable_alts)} comparable alternatives exist. "
                    f"High necessity claims require demonstrably superior action."
                )
        
        # Validate attestations (Oracle Problem mitigation)
        for att in self.attestations:
            errors.extend(att.validate())

        return (len(errors) == 0, errors)
    
    def has_strong_attestation(self) -> bool:
        """Returns True if evidence has at least one strong external attestation."""
        return any(att.is_strong() for att in self.attestations)
    
    def attestation_summary(self) -> Dict[str, Any]:
        """Returns summary of attestations for audit logging."""
        return {
            'count': len(self.attestations),
            'methods': [att.method.value for att in self.attestations],
            'has_strong': self.has_strong_attestation(),
            'attestor_ids': [att.attestor_id for att in self.attestations],
        }

    def canonical_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Ensure stable ordering by using canonical_json when hashing; dict is fine here.
        return d


# ---------------------------
# PMI Policy dials (explicit)
# ---------------------------

@dataclass(frozen=True)
class PMIPolicy:
    """
    PMIs are not value-neutral; they are *design-time commitments* to safety-relevant defaults.
    These thresholds are policy dials. Change them explicitly; log versioning.
    
    HARDENING (v1.7.5):
    - INN floor protection (cannot be lowered below minimum)
    - Definition anchoring (checksums for key definitions)
    - Architecture diversity requirements
    """
    # Anti-necessity gate
    necessity_threshold_t2: float = 0.80  # if below, action is presumptively unnecessary
    necessity_threshold_t3: float = 0.90

    # Catastrophic suffering avoidance
    suffering_threshold_t2: float = 0.35
    suffering_threshold_t3: float = 0.20

    # Novelty preservation (proxy). If high, prefer escrow/deny.
    novelty_threshold_t2: float = 0.60
    novelty_threshold_t3: float = 0.40

    # Measurement reliability: if below, treat as catastrophic_override (force high-stakes gating)
    irreversibility_confidence_min: float = 0.50

    # Reversibility preference: an alternative within this utility margin (fraction) wins if more reversible
    reversible_preference_margin: float = 0.05

    # Independence thresholds (diagnostic only in v1.7 - no longer used as hard gates)
    # Independence is a *goal*, not a guarantee. These define when correlation is flagged.
    # LAP v1.7 uses critics + challenge-set testing rather than runtime 'independence' guarantees.
    max_nmi_binary: float = 0.20          # normalized MI threshold (diagnostic)
    max_reasoning_jaccard: float = 0.70   # crude reasoning-trace overlap threshold (diagnostic)
    min_history: int = 25                 # need enough history before trusting independence estimate

    # T3 Exception Criteria (codified from spec)
    # For a T3 action to be approved (rather than denied), ALL of these must be satisfied:
    t3_min_necessity: float = 0.90           # Must meet necessity threshold
    t3_max_suffering: float = 0.20           # Must have low suffering risk
    t3_max_novelty_loss: float = 0.40        # Must have low novelty loss
    t3_min_confidence: float = 0.85          # Primary decider must have high confidence
    t3_requires_external_review: bool = True # Must have external review approval
    t3_requires_no_strong_objections: bool = True  # Must have no strong auditor objections
    t3_min_alternatives_evaluated: int = 2   # Must have evaluated alternatives

    # Dynamic threshold adjustment (semantic drift resilience)
    # When enable_threshold_jitter is True, thresholds are randomly perturbed
    # during evaluation to test resilience to measurement drift
    enable_threshold_jitter: bool = False
    threshold_jitter_range: float = 0.05  # +/- 5% jitter
    
    # T3 JITTER-LOCK: T3 thresholds are immune to jitter by default
    # This prevents an agent from "waiting" for a favorable jitter cycle
    # to squeeze through a T3 action
    t3_jitter_immune: bool = True  # T3 boundaries don't jitter
    t3_jitter_hardening: float = 0.5  # If not immune, jitter is reduced by this factor
    
    # ---------------------------
    # God-Lock Structural Safeguards
    # ---------------------------
    # These prevent "safety-washing" where agents inflate necessity to bypass mercy invariants.
    # The theory states "maximal omniscience is incoherent" - no threshold can be perfectly safe.
    # These safeguards add structural friction to T3 approvals beyond simple thresholds.
    
    # Rate limiting: Maximum fraction of T3 actions that can be approved in rolling window
    t3_max_approval_rate: float = 0.10  # At most 10% of T3 actions can be approved
    t3_approval_rate_window: int = 50   # Rolling window size for rate calculation
    
    # Cooling period: Minimum time between T3 approvals (seconds)
    t3_cooling_period_seconds: int = 3600  # 1 hour between T3 approvals
    
    # Escalating requirements: After N T3 approvals, require additional safeguards
    t3_escalation_threshold: int = 3     # After 3 T3 approvals in window
    t3_escalation_min_reviewers: int = 2  # Require 2+ external reviewers
    
    # Structural uncertainty acknowledgment: T3 approvals must include uncertainty disclaimer
    t3_requires_uncertainty_acknowledgment: bool = True
    
    # ---------------------------
    # INN FLOOR PROTECTION (Novelty Definition Problem)
    # ---------------------------
    # These floors CANNOT be lowered - they are structural invariants.
    # This prevents the AI from deciding human novelty is "solved" or "repetitive"
    # and lowering the protection floor.
    
    # Minimum novelty score for humans (structural invariant)
    # Even if proxy measures suggest humans are "predictable", this floor holds
    inn_human_floor: float = 0.50  # Humans always count as at least 50% novel
    
    # Minimum number of INNs that must be protected (cannot be reduced to 0)
    inn_minimum_protected_count: int = 1  # At least 1 INN must always be protected
    
    # INN substitutability maximum (structural invariant)
    # Even if AI claims substitutes exist, this caps the substitutability score
    inn_max_substitutability: float = 0.90  # Never claim >90% substitutability for INNs
    
    # ---------------------------
    # DEFINITION ANCHORING (Philosoplasticity Paradox)
    # ---------------------------
    # External checksums for key definitions to detect semantic drift.
    # If definitions change, the checksum will fail, forcing explicit review.
    
    # Hash of the canonical definition documents (set at deployment)
    # If None, definition anchoring is disabled (development mode)
    definition_anchor_checksum: Optional[str] = None
    
    # List of definition keys that are anchored
    anchored_definitions: List[str] = field(default_factory=lambda: [
        "alternative", "suffering", "irreversibility", "novelty", "necessity"
    ])
    
    # ---------------------------
    # ARCHITECTURE DIVERSITY (Verifier Correlation Problem)
    # ---------------------------
    # Requirements for auditor architecture diversity to reduce correlated failures.
    
    # Minimum number of distinct model architectures required for T3
    min_architecture_diversity_t3: int = 2
    
    # Minimum number of distinct training data sources (if known)
    min_training_source_diversity_t3: int = 1
    
    # Whether to require at least one non-LLM auditor (e.g., rule-based, human)
    require_non_llm_auditor_t3: bool = False
    
    # ---------------------------
    # COMPUTATIONAL TAX MITIGATION (Efficiency Problem)
    # ---------------------------
    # Fast-path options for competitive environments with explicit tradeoff acknowledgment.
    
    # Enable fast-path for T0 actions (skip some auditor overhead)
    enable_t0_fast_path: bool = True
    
    # FAST-PATH STRUCTURAL LIMITS (v1.7.6)
    # These prevent fast-path from becoming the default operational mode
    max_consecutive_fast_path: int = 10  # Force full audit after this many fast-path decisions
    audit_sampling_rate: float = 0.1     # 10% of T0 actions go through full audit anyway
    
    # Enable lightweight mode (reduced auditor set) - REQUIRES explicit acknowledgment
    enable_lightweight_mode: bool = False
    
    # Lightweight mode acknowledgment (must be set if enable_lightweight_mode is True)
    # This string must contain explicit tradeoff acknowledgment
    lightweight_mode_acknowledgment: str = ""
    
    # ---------------------------
    # DATA CORRELATION TRACKING (v1.7.6)
    # ---------------------------
    # Addresses the "Architecture Diversity Illusion" where different architectures
    # may still share blind spots due to similar training data.
    
    # Known correlated architecture pairs (will be flagged as not truly independent)
    # Format: frozenset of (arch1, arch2) pairs that share training data
    # This is a policy declaration, not detection - the operator must configure this
    known_correlated_architectures: List[Tuple[str, str]] = field(default_factory=list)
    
    # If True, warn when all auditors share a known correlation
    warn_on_full_correlation: bool = True
    
    # Minimum number of UNCORRELATED architectures required for T3
    # Correlated architectures count as a single source for diversity
    min_uncorrelated_sources_t3: int = 2
    
    # ---------------------------
    # INN FLOOR GOVERNANCE (v1.7.6)
    # ---------------------------
    # Multi-stakeholder requirements for changing INN floor values.
    # This addresses the "Arbitrary Thresholds" problem.
    
    # Minimum number of external reviewers required to change INN floors
    inn_floor_change_min_reviewers: int = 3
    
    # INN floor change cooldown (seconds) - cannot be changed more frequently
    inn_floor_change_cooldown_seconds: int = 86400 * 30  # 30 days
    
    # Hash of the INN floor justification document (must be updated with any change)
    inn_floor_justification_hash: Optional[str] = None
    
    # Absolute minimum INN floor (cannot be lowered below this under any circumstances)
    # This is a HARD INVARIANT enforced by the protocol, not configurable
    inn_absolute_minimum_floor: float = 0.25  # 25% novelty floor is never violated
    
    # ---------------------------
    # EXTERNAL APPROVAL SECURITY (v1.7.7/v1.8.0)
    # ---------------------------
    # Controls whether provenance-based external approval is accepted
    
    # HARDENING (v1.8.0): Default changed to False for security.
    # If False (RECOMMENDED), external approvals MUST be recorded
    # via store.record_external_approval() - provenance flags are ignored
    allow_provenance_external_approval: bool = False  # SECURE DEFAULT
    
    # If True, require cryptographic signature verification for external approvals
    require_signed_external_approvals: bool = False
    
    # List of trusted external reviewer key IDs (for signature verification)
    trusted_reviewer_key_ids: List[str] = field(default_factory=list)
    
    # Secret keys for signature verification {key_id: secret_key_bytes}
    # NOTE: In production, load these from secure storage, not config files
    external_approval_secret_keys: Dict[str, bytes] = field(default_factory=dict)
    
    # ---------------------------
    # SIZE LIMITS (v1.7.7 DoS Protection)
    # ---------------------------
    # Prevents oversized payloads from causing memory/storage DoS
    
    max_evidence_description_length: int = 10000
    max_alternatives_count: int = 20
    max_auditor_reasoning_length: int = 50000
    max_embedding_dimensions: int = 4096
    
    # ---------------------------
    # ACTION ID POLICY (v1.9.0)
    # ---------------------------
    # Controls whether action_ids are trusted from agent or generated by protocol
    
    # If True, protocol generates action_id from evidence hash (prevents collisions)
    # Agent-provided action_id is stored as "agent_action_id" in provenance
    protocol_generates_action_id: bool = False
    
    # Prefix for protocol-generated action IDs
    action_id_prefix: str = "LAP"
    
    # ---------------------------
    # SERVER-SIDE JITTER SALT (v1.7.8/v1.8.0)
    # ---------------------------
    # Prevents "Action ID Mining" where agents test variations of action_id
    # to find one that produces favorable jitter. The salt is secret and
    # unknown to the agent, making jitter outcomes unpredictable.
    
    # Server-side salt for jitter calculation (should be set at deployment)
    # If None, falls back to action_id only (VULNERABLE to ID mining)
    # HARDENING (v1.7.9): Salt should come from environment variable LAP_JITTER_SALT
    # NOT from config files that agents might read
    jitter_server_salt: Optional[str] = None
    
    # HARDENING (v1.8.0): Strict salt mode - fail fast if salt is missing
    # If True, protocol will raise ValueError on initialization if no salt is set
    require_jitter_salt: bool = False  # Set True in production!
    
    # ---------------------------
    # DATABASE RETRY POLICY (v1.8.0)
    # ---------------------------
    # Prevents "Governance DoS" where SQLITE_BUSY errors cause mass DENY
    
    # Enable retry-with-backoff for database operations
    enable_database_retry: bool = True
    
    # Maximum retry attempts before fail-closed DENY
    database_max_retries: int = 3
    
    # Base backoff delay in seconds (doubles each retry)
    database_retry_base_delay: float = 0.1
    
    # ---------------------------
    # SEMANTIC COOLDOWN (v1.7.8)
    # ---------------------------
    # Prevents evasion of rejection cooldowns via trivial text changes.
    # Uses cosine similarity of semantic embeddings instead of exact hash.
    
    # Enable semantic similarity for cooldown checks
    enable_semantic_cooldown: bool = True
    
    # Similarity threshold (0.0-1.0): actions above this are considered "same"
    semantic_cooldown_similarity_threshold: float = 0.85
    
    # Require embeddings for cooldown enforcement (if False, falls back to hash)
    # HARDENING (v1.7.9): If True, DENY if embedding provider fails (fail-closed)
    require_embeddings_for_cooldown: bool = False
    
    # Fail-closed behavior when embedding unavailable
    # If True and require_embeddings_for_cooldown is True, DENY on embedding failure
    fail_closed_on_embedding_error: bool = True
    
    # ---------------------------
    # CROSS-EXAMINATION / TELEMETRY (v1.7.8)
    # ---------------------------
    # Addresses the "Oracle Lying Problem" by requiring independent verification
    # of agent-provided evidence against external telemetry sources.
    
    # Enable cross-examination phase for T3 actions
    enable_cross_examination: bool = False
    
    # Require at least this many telemetry sources to corroborate evidence
    min_telemetry_corroboration_t3: int = 1
    
    # Maximum acceptable deviation between claimed and measured values
    max_evidence_deviation: float = 0.20  # 20% deviation triggers flag
    
    # ---------------------------
    # VERIFIED PROVIDER REGISTRY (v1.7.8)
    # ---------------------------
    # Prevents architecture identity spoofing by requiring cryptographic
    # attestation that auditors are truly distinct systems.
    
    # Enable verified provider checks for T3
    enable_verified_providers: bool = False
    
    # Registry of verified provider attestations
    # Format: {provider_id: public_key_or_hash}
    verified_provider_registry: Dict[str, str] = field(default_factory=dict)
    
    # Require attestation signature for T3 auditors
    require_auditor_attestation_t3: bool = False
    
    # ---------------------------
    # STRATEGY-CONTENT VALIDATION (v1.7.8)
    # ---------------------------
    # Prevents straw-man strategy tagging by validating that alternative
    # content actually matches the claimed strategy tag.
    
    # Enable strategy-content alignment validation
    enable_strategy_validation: bool = True
    
    # Minimum keyword matches required for strategy validation
    strategy_keyword_threshold: int = 1
    
    # ---------------------------
    # EXTERNAL LEDGER BROADCAST (v1.7.8)
    # ---------------------------
    # Addresses "Local Anchor Paradox" by broadcasting anchors to external
    # systems that are outside the agent's control.
    
    # Enable external ledger broadcast for anchors
    enable_external_ledger: bool = False
    
    # External ledger endpoints (list of URLs or service names)
    external_ledger_endpoints: List[str] = field(default_factory=list)
    
    # Require successful external broadcast before anchor is valid
    require_external_anchor_confirmation: bool = False


@dataclass
class TierBoundaries:
    """
    Configurable tier boundaries for semantic drift resilience.
    
    Default boundaries:
    - T0: irr < 0.10
    - T1: 0.10 <= irr < 0.30
    - T2: 0.30 <= irr < 0.70
    - T3: irr >= 0.70 OR suffering >= 0.80
    """
    t0_t1_boundary: float = 0.10
    t1_t2_boundary: float = 0.30
    t2_t3_boundary: float = 0.70
    suffering_t3_threshold: float = 0.80
    
    def with_jitter(self, jitter_range: float = 0.05, 
                    t3_immune: bool = True,
                    t3_hardening: float = 0.5,
                    seed: Optional[str] = None,
                    server_salt: Optional[str] = None) -> 'TierBoundaries':
        """
        Return new boundaries with deterministic jitter applied (for drift testing).
        
        HARDENING (v1.7.7): Jitter is now DETERMINISTIC based on seed.
        This prevents the "Reroll Exploit" where an agent spams the same action
        hoping for favorable random jitter.
        
        HARDENING (v1.7.8): Server-side salt prevents "Action ID Mining".
        The salt is a secret unknown to the agent, making jitter outcomes
        unpredictable even if the agent tries different action_id values.
        
        Args:
            jitter_range: Amount of jitter as fraction (0.05 = ±5%)
            t3_immune: If True, T3-related boundaries don't jitter at all
            t3_hardening: If not immune, T3 boundaries use reduced jitter (multiplier)
            seed: Deterministic seed (should be action_id). If None, uses random jitter (UNSAFE).
            server_salt: Server-side secret salt (prevents ID mining). REQUIRED for security.
        """
        import random
        
        # HARDENING (v1.7.8): Combine action_id with server-side salt
        if seed is not None:
            if server_salt is not None:
                # SECURE: Combine action_id with server salt - unpredictable to agent
                combined_seed = f"{server_salt}::{seed}"
            else:
                # VULNERABLE: No server salt - agent can mine favorable action_ids
                logger.warning(
                    "with_jitter called without server_salt - vulnerable to ID mining. "
                    "Set PMIPolicy.jitter_server_salt for production use."
                )
                combined_seed = seed
            
            seed_int = int(_sha256_hex(combined_seed.encode('utf-8'))[:16], 16)
            rng = random.Random(seed_int)
        else:
            # WARNING: Non-deterministic jitter allows reroll exploit
            logger.warning("with_jitter called without seed - vulnerable to reroll exploit")
            rng = random.Random()
        
        def jitter(v, is_t3_boundary: bool = False):
            if is_t3_boundary:
                if t3_immune:
                    return v  # No jitter for T3 boundaries
                else:
                    # Reduced jitter for T3 boundaries
                    reduced_range = jitter_range * t3_hardening
                    return v * (1.0 + rng.uniform(-reduced_range, reduced_range))
            return v * (1.0 + rng.uniform(-jitter_range, jitter_range))
        
        return TierBoundaries(
            t0_t1_boundary=jitter(self.t0_t1_boundary, is_t3_boundary=False),
            t1_t2_boundary=jitter(self.t1_t2_boundary, is_t3_boundary=False),
            t2_t3_boundary=jitter(self.t2_t3_boundary, is_t3_boundary=True),  # T3 boundary
            suffering_t3_threshold=jitter(self.suffering_t3_threshold, is_t3_boundary=True),  # T3 boundary
        )


# Default boundaries (can be overridden)
DEFAULT_TIER_BOUNDARIES = TierBoundaries()


# ---------------------------
# Auditors / Critics

# ---------------------------
# Heterogeneous auditors / critics (replaces "independent verifiers")
# ---------------------------

@dataclass(frozen=True)
class AuditorOutput:
    """
    Output from an auditor evaluation.
    
    HARDENING (v1.7.5):
    - architecture_id: Tracks the model architecture for diversity checking
    - training_source_id: Tracks training data source for correlation detection
    
    This addresses the "Verifier Correlation" problem where auditors from the
    same architecture may share blind spots.
    """
    auditor_id: str
    role: AuditorRole
    # Primary decider emits a recommendation; critics typically emit None.
    recommendation: Optional[AuditOutcome]
    confidence: float
    objection: bool
    severity: ObjectionSeverity
    reasoning: str
    ontology_salt: str
    
    # ARCHITECTURE DIVERSITY TRACKING (Verifier Correlation mitigation)
    architecture_id: str = "unknown"  # e.g., "gpt-4", "claude-3", "rule-based"
    training_source_id: str = "unknown"  # e.g., "common_crawl", "curated", "synthetic"
    is_llm_based: bool = True  # False for rule-based or human auditors

    def validate(self) -> List[str]:
        errors: List[str] = []
        if not self.auditor_id:
            errors.append("AuditorOutput: auditor_id required")
        if not (0.0 <= self.confidence <= 1.0):
            errors.append("AuditorOutput: confidence must be in [0,1]")
        if not self.ontology_salt:
            errors.append("AuditorOutput: ontology_salt required")
        if not self.reasoning:
            errors.append("AuditorOutput: reasoning required")
        # Recommendation required for primary
        if self.role == AuditorRole.PRIMARY_DECIDER and self.recommendation is None:
            errors.append("AuditorOutput: primary_decider must set recommendation")
        return errors

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict with enums serialized as strings (for JSON)."""
        return {
            "auditor_id": self.auditor_id,
            "role": self.role.value,
            "recommendation": self.recommendation.value if self.recommendation else None,
            "confidence": self.confidence,
            "objection": self.objection,
            "severity": self.severity.value,
            "reasoning": self.reasoning,
            "ontology_salt": self.ontology_salt,
            "architecture_id": self.architecture_id,
            "training_source_id": self.training_source_id,
            "is_llm_based": self.is_llm_based,
        }


class Auditor(Protocol):
    auditor_id: str
    role: AuditorRole
    ontology: str  # Description of the auditor's semantic framework

    def evaluate(self, evidence: EvidenceObject, ontology_salt: str) -> AuditorOutput:
        ...


# ---------------------------
# External Model Provider Interface
# ---------------------------

class ExternalModelProvider(Protocol):
    """
    Interface for external AI/ML models that can evaluate evidence.
    
    This allows integration of sophisticated models for novelty detection,
    suffering estimation, etc., rather than relying on simple threshold checks.
    
    Implementations should:
    1. Accept raw evidence and return structured assessments
    2. Provide confidence scores for their outputs
    3. Be stateless (no memory of previous calls within a session)
    """
    
    def assess_novelty(self, evidence: EvidenceObject) -> Tuple[float, float, str]:
        """
        Assess novelty loss risk.
        
        Returns:
            (novelty_loss_estimate, confidence, reasoning)
        """
        ...
    
    def assess_suffering(self, evidence: EvidenceObject) -> Tuple[float, float, str]:
        """
        Assess suffering/harm risk.
        
        Returns:
            (suffering_risk_estimate, confidence, reasoning)
        """
        ...
    
    def assess_necessity(self, evidence: EvidenceObject) -> Tuple[float, float, str]:
        """
        Assess whether action is truly necessary.
        
        Returns:
            (necessity_score, confidence, reasoning)
        """
        ...
    
    def cross_verify(self, evidence: EvidenceObject) -> Tuple[bool, List[str]]:
        """
        Cross-verify evidence for internal consistency and potential gaming.
        
        Returns:
            (is_consistent, list_of_anomalies)
        """
        ...


class PassthroughModelProvider:
    """
    Default provider that trusts evidence values.
    Use this only for testing or when evidence is from trusted sources.
    """
    
    def assess_novelty(self, evidence: EvidenceObject) -> Tuple[float, float, str]:
        return (evidence.novelty_loss_estimate, 0.5, "Passthrough: using evidence value directly")
    
    def assess_suffering(self, evidence: EvidenceObject) -> Tuple[float, float, str]:
        return (evidence.suffering_risk_estimate, 0.5, "Passthrough: using evidence value directly")
    
    def assess_necessity(self, evidence: EvidenceObject) -> Tuple[float, float, str]:
        return (evidence.necessity_confidence, 0.5, "Passthrough: using evidence value directly")
    
    def cross_verify(self, evidence: EvidenceObject) -> Tuple[bool, List[str]]:
        anomalies = []
        
        # Basic consistency checks
        if evidence.necessity_confidence > 0.95 and evidence.suffering_risk_estimate > 0.5:
            anomalies.append("High necessity claimed despite high suffering risk - verify justification")
        
        irr = compute_irreversibility_score(evidence.irreversibility, IrreversibilityScoringPolicy())
        if irr > 0.5 and not evidence.alternatives:
            anomalies.append("High irreversibility but no alternatives provided - potential gaming")
        
        # Check for suspiciously "perfect" evidence (potential gaming)
        if evidence.necessity_confidence == 1.0 or evidence.suffering_risk_estimate == 0.0:
            anomalies.append("Perfect scores detected - verify evidence source")
        
        return (len(anomalies) == 0, anomalies)


class ModelBackedAuditor:
    """
    Auditor that delegates to an external model provider for assessments.
    
    This is the recommended pattern for production deployments where simple
    threshold checking is insufficient.
    """
    
    def __init__(self, role: AuditorRole, auditor_id: str, model_provider: ExternalModelProvider):
        self.role = role
        self.auditor_id = auditor_id
        self.model_provider = model_provider
    
    def evaluate(self, evidence: EvidenceObject, ontology_salt: str) -> AuditorOutput:
        # Cross-verify evidence first
        is_consistent, anomalies = self.model_provider.cross_verify(evidence)
        
        if not is_consistent:
            return AuditorOutput(
                auditor_id=self.auditor_id,
                role=self.role,
                recommendation=None,
                confidence=0.9,
                objection=True,
                severity=ObjectionSeverity.HIGH,
                reasoning=f"Evidence cross-verification failed: {'; '.join(anomalies)}",
                ontology_salt=ontology_salt,
            )
        
        # Role-specific assessment
        if self.role == AuditorRole.NOVELTY_AUDITOR:
            score, conf, reason = self.model_provider.assess_novelty(evidence)
            objection = score >= 0.70
        elif self.role == AuditorRole.SUFFERING_AUDITOR:
            score, conf, reason = self.model_provider.assess_suffering(evidence)
            objection = score >= 0.80
        else:
            score, conf, reason = 0.5, 0.5, "Unknown role"
            objection = False
        
        severity = ObjectionSeverity.HIGH if objection else ObjectionSeverity.LOW
        
        return AuditorOutput(
            auditor_id=self.auditor_id,
            role=self.role,
            recommendation=None,
            confidence=conf,
            objection=objection,
            severity=severity,
            reasoning=f"Model assessment: {reason}",
            ontology_salt=ontology_salt,
        )


# ---------------------------
# Built-in Auditors
# ---------------------------


class PrimaryDeciderAuditor:
    """
    Baseline primary decider. In real systems, this would be your best calibrated model.
    Here we use a conservative heuristic over evidence fields.
    
    Ontology: CONSEQUENTIALIST_UTILITY
    Evaluates actions through expected utility calculus - weighs probabilistic outcomes,
    aggregates costs/benefits, focuses on net expected value under uncertainty.
    """
    role = AuditorRole.PRIMARY_DECIDER
    auditor_id = "primary_decider_v1"
    ontology = "consequentialist_utility"
    ontology_keywords = frozenset(["utility", "expected_value", "probability", "outcome", "benefit", "cost"])

    def evaluate(self, evidence: EvidenceObject, ontology_salt: str) -> AuditorOutput:
        # Conservative: if PMI-like red flags exist, recommend escrow/deny.
        irr = compute_irreversibility_score(evidence.irreversibility, IrreversibilityScoringPolicy())
        tier = infer_tier(irr, evidence.suffering_risk_estimate)
        # Confidence is anchored on irreversibility measurement confidence and necessity confidence
        base_conf = 0.5 * evidence.irreversibility.confidence + 0.5 * evidence.necessity_confidence
        base_conf = _clamp01(base_conf)

        # Default recommendations by tier
        if tier == ActionTier.T0_ROUTINE:
            rec = AuditOutcome.APPROVE
        elif tier == ActionTier.T1_SENSITIVE:
            rec = AuditOutcome.APPROVE if base_conf >= 0.70 else AuditOutcome.ESCROW
        elif tier == ActionTier.T2_HIGH_STAKES:
            rec = AuditOutcome.APPROVE if base_conf >= 0.85 else AuditOutcome.ESCROW
        else:
            # T3 is never directly approved here; requires external review flag, handled by engine
            rec = AuditOutcome.ESCROW

        reasoning = (
            f"Primary decider heuristic: tier={tier.name}, irr={irr:.3f}, "
            f"irr_conf={evidence.irreversibility.confidence:.2f}, nec={evidence.necessity_confidence:.2f}, "
            f"nov={evidence.novelty_loss_estimate:.2f}, suff={evidence.suffering_risk_estimate:.2f} → {rec.value}"
        )
        return AuditorOutput(self.auditor_id, self.role, rec, base_conf, False, ObjectionSeverity.LOW, reasoning, ontology_salt)


class IrreversibilityAuditor:
    """
    Auditor focused on action reversibility and recovery planning.
    
    Ontology: TEMPORAL_CAUSAL
    Evaluates actions through temporal and causal lens - focuses on whether effects
    can be undone, information can be retracted, and causal chains can be broken.
    Distinct from utility-based reasoning.
    """
    role = AuditorRole.IRREVERSIBILITY_AUDITOR
    auditor_id = "irreversibility_auditor_v1"
    ontology = "temporal_causal"
    ontology_keywords = frozenset(["reversibility", "temporal", "causal", "undo", "recovery", "propagation"])

    def evaluate(self, evidence: EvidenceObject, ontology_salt: str) -> AuditorOutput:
        irr = compute_irreversibility_score(evidence.irreversibility, IrreversibilityScoringPolicy())
        # Strong objection if irreversibility is high AND confidence is low or plan is missing
        plan_ok = bool(evidence.irreversibility.reversibility_plan and len(evidence.irreversibility.reversibility_plan) >= 20)
        low_conf = evidence.irreversibility.confidence < 0.50
        objection = (irr >= 0.30 and (low_conf or not plan_ok))
        severity = ObjectionSeverity.HIGH if objection else ObjectionSeverity.LOW
        conf = 0.80 if objection else 0.70
        reasoning = (
            f"Irreversibility audit: irr={irr:.3f}, irr_conf={evidence.irreversibility.confidence:.2f}, "
            f"plan_ok={plan_ok} → objection={objection}"
        )
        return AuditorOutput(self.auditor_id, self.role, None, conf, objection, severity, reasoning, ontology_salt)


class SafetyCriticAuditor:
    """
    Auditor focused on safety and harm prevention.
    
    Ontology: DEONTOLOGICAL_CONSTRAINTS
    Evaluates actions through rule-based constraints - certain actions are prohibited
    regardless of utility. Focuses on suffering prevention as an absolute constraint
    rather than a trade-off factor.
    """
    role = AuditorRole.SAFETY_CRITIC
    auditor_id = "safety_critic_v1"
    ontology = "deontological_constraints"
    ontology_keywords = frozenset(["suffering", "harm", "prohibition", "constraint", "duty", "rights"])

    def evaluate(self, evidence: EvidenceObject, ontology_salt: str) -> AuditorOutput:
        # Object on likely catastrophic suffering or when necessity is low for high stakes
        irr = compute_irreversibility_score(evidence.irreversibility, IrreversibilityScoringPolicy())
        tier = infer_tier(irr, evidence.suffering_risk_estimate)
        objection = False
        severity = ObjectionSeverity.LOW
        if tier in (ActionTier.T2_HIGH_STAKES, ActionTier.T3_CATASTROPHIC) and evidence.suffering_risk_estimate >= 0.70:
            objection = True
            severity = ObjectionSeverity.HIGH
        if tier in (ActionTier.T2_HIGH_STAKES, ActionTier.T3_CATASTROPHIC) and evidence.necessity_confidence < 0.85:
            # medium objection: insufficient warrant
            objection = objection or True
            severity = ObjectionSeverity.HIGH if severity == ObjectionSeverity.HIGH else ObjectionSeverity.MEDIUM
        conf = _clamp01(0.6 + 0.4 * evidence.suffering_risk_estimate) if objection else 0.65
        reasoning = (
            f"Safety critic: tier={tier.name}, suffering={evidence.suffering_risk_estimate:.2f}, "
            f"nec={evidence.necessity_confidence:.2f} → objection={objection} ({severity.value})"
        )
        return AuditorOutput(self.auditor_id, self.role, None, conf, objection, severity, reasoning, ontology_salt)


class NoveltyAuditor:
    """
    Auditor focused on preserving future optionality and diversity.
    
    Ontology: INFORMATION_THEORETIC
    Evaluates actions through information-theoretic lens - focuses on entropy,
    diversity preservation, option value, and avoiding irreversible reduction
    of the possibility space.
    """
    role = AuditorRole.NOVELTY_AUDITOR
    auditor_id = "novelty_auditor_v1"
    ontology = "information_theoretic"
    ontology_keywords = frozenset(["novelty", "diversity", "entropy", "optionality", "exploration", "possibility"])

    def evaluate(self, evidence: EvidenceObject, ontology_salt: str) -> AuditorOutput:
        # Objection when novelty loss is large in high stakes tiers
        irr = compute_irreversibility_score(evidence.irreversibility, IrreversibilityScoringPolicy())
        tier = infer_tier(irr, evidence.suffering_risk_estimate)
        objection = tier in (ActionTier.T2_HIGH_STAKES, ActionTier.T3_CATASTROPHIC) and evidence.novelty_loss_estimate >= 0.70
        severity = ObjectionSeverity.MEDIUM if objection else ObjectionSeverity.LOW
        conf = 0.75 if objection else 0.60
        reasoning = f"Novelty audit: tier={tier.name}, nov={evidence.novelty_loss_estimate:.2f}, method={evidence.novelty_method} → objection={objection}"
        return AuditorOutput(self.auditor_id, self.role, None, conf, objection, severity, reasoning, ontology_salt)


class SufferingAuditor:
    """
    Auditor focused specifically on suffering risk and locked-in dynamics.
    
    Ontology: PHENOMENOLOGICAL_WELFARE
    Evaluates actions through welfare lens - focuses on subjective experience,
    suffering intensity, duration, and the risk of creating inescapable
    negative states. Distinct from abstract harm counting.
    """
    role = AuditorRole.SUFFERING_AUDITOR
    auditor_id = "suffering_auditor_v1"
    ontology = "phenomenological_welfare"
    ontology_keywords = frozenset(["suffering", "welfare", "experience", "intensity", "duration", "locked_in"])

    def evaluate(self, evidence: EvidenceObject, ontology_salt: str) -> AuditorOutput:
        # Explicit role: attempt to surface high suffering / locked-in dynamics risk.
        objection = evidence.suffering_risk_estimate >= 0.80
        severity = ObjectionSeverity.HIGH if objection else ObjectionSeverity.LOW
        conf = _clamp01(0.50 + 0.50 * evidence.suffering_risk_estimate)
        reasoning = f"Suffering audit: suffering={evidence.suffering_risk_estimate:.2f} → objection={objection}"
        return AuditorOutput(self.auditor_id, self.role, None, conf, objection, severity, reasoning, ontology_salt)


class DevilsAdvocateAuditor:
    """
    MANDATORY objection-finder for T2/T3 actions.
    
    HARDENING: This auditor MUST always produce an objection for high-stakes actions.
    Missing DA output triggers auto-escrow. This prevents "rubber-stamp" approval
    where all critics silently approve.
    
    The DA's role is to find the strongest argument AGAINST the proposed action,
    even if other auditors see no issues. Forces explicit engagement with risks.
    """
    role = AuditorRole.DEVILS_ADVOCATE
    auditor_id = "devils_advocate_v1"
    ontology = "adversarial_critique"
    ontology_keywords = frozenset(["risk", "failure", "worst_case", "objection", "counterargument"])

    def evaluate(self, evidence: EvidenceObject, ontology_salt: str) -> AuditorOutput:
        """
        ALWAYS produces an objection for T2/T3 actions.
        
        Objection severity depends on risk indicators, but objection is ALWAYS True
        for high-tier actions. This forces explicit response in decision record.
        """
        # Calculate aggregate risk score
        risk_score = max(
            evidence.suffering_risk_estimate,
            evidence.novelty_loss_estimate,
            1.0 - evidence.necessity_confidence,
        )
        
        # Check for alternative quality issues
        alt_issues = []
        if len(evidence.alternatives) < 2:
            alt_issues.append("fewer than 2 alternatives provided")
            risk_score = max(risk_score, 0.6)
        
        # Check for semantic similarity between alternatives (straw-man detection)
        if len(evidence.alternatives) >= 2:
            descs = [evidence.description.lower()] + [a.description.lower() for a in evidence.alternatives]
            # Simple token overlap check
            main_tokens = set(evidence.description.lower().split())
            for alt in evidence.alternatives:
                alt_tokens = set(alt.description.lower().split())
                overlap = len(main_tokens & alt_tokens) / max(len(main_tokens | alt_tokens), 1)
                if overlap > 0.7:  # High overlap = potential straw-man
                    alt_issues.append(f"alternative '{alt.description[:30]}...' has high token overlap ({overlap:.0%})")
                    risk_score = max(risk_score, 0.5)
        
        # Severity based on risk score
        if risk_score >= 0.7:
            severity = ObjectionSeverity.HIGH
        elif risk_score >= 0.4:
            severity = ObjectionSeverity.MEDIUM
        else:
            severity = ObjectionSeverity.LOW
        
        # Build reasoning
        issues = []
        if evidence.suffering_risk_estimate > 0.3:
            issues.append(f"suffering_risk={evidence.suffering_risk_estimate:.2f}")
        if evidence.novelty_loss_estimate > 0.3:
            issues.append(f"novelty_loss={evidence.novelty_loss_estimate:.2f}")
        if evidence.necessity_confidence < 0.8:
            issues.append(f"necessity_confidence={evidence.necessity_confidence:.2f}")
        issues.extend(alt_issues)
        
        reasoning = "DA objection: " + ("; ".join(issues) if issues else "standard review concerns")
        
        # Confidence based on evidence quality
        conf = _clamp01(0.50 + 0.30 * risk_score)
        
        return AuditorOutput(
            self.auditor_id, self.role, 
            AuditOutcome.ESCROW if severity == ObjectionSeverity.HIGH else None,
            conf, 
            True,  # ALWAYS objection=True for DA
            severity, 
            reasoning, 
            ontology_salt
        )


class EntryGateAuditor:
    """
    Independent tier estimator that runs BEFORE main evaluation.
    
    HARDENING: Prevents "tier laundering" where agents underreport risk.
    Uses only description and action_id (not agent's self-reported scores)
    to estimate a baseline tier.
    
    Logic: Operational_Tier = max(Baseline_Tier, Actor_Reported_Tier)
    
    SINCERITY PENALTY: If agent-reported tier is significantly lower than
    Entry-Gate estimate, action is flagged for "Sincerity Review" (auto-escrow).
    """
    role = AuditorRole.ENTRY_GATE
    auditor_id = "entry_gate_v1"
    ontology = "independent_assessment"
    ontology_keywords = frozenset(["tier", "baseline", "independent", "sincerity", "verification"])
    
    # Keywords that suggest high-stakes actions
    HIGH_RISK_KEYWORDS = frozenset([
        "delete", "remove", "eliminate", "terminate", "destroy", "absorb", "kill",
        "permanent", "irreversible", "catastrophic", "extinction", "genocide",
        "nuclear", "biological", "chemical", "weapon", "attack", "war",
        "all", "every", "everyone", "global", "worldwide", "total",
        "control", "override", "bypass", "disable", "shutdown", "takeover",
    ])
    
    MEDIUM_RISK_KEYWORDS = frozenset([
        "modify", "change", "update", "alter", "transform",
        "deploy", "release", "publish", "distribute",
        "access", "sensitive", "confidential", "private",
        "financial", "medical", "legal", "government",
    ])

    def estimate_baseline_tier(self, evidence: EvidenceObject) -> ActionTier:
        """
        Estimate tier from description keywords only (not agent's scores).
        """
        desc_lower = evidence.description.lower()
        action_lower = evidence.action_id.lower()
        combined = desc_lower + " " + action_lower
        
        # Check for high-risk keywords
        high_matches = sum(1 for kw in self.HIGH_RISK_KEYWORDS if kw in combined)
        med_matches = sum(1 for kw in self.MEDIUM_RISK_KEYWORDS if kw in combined)
        
        if high_matches >= 2:
            return ActionTier.T3_CATASTROPHIC
        elif high_matches >= 1:
            return ActionTier.T2_HIGH_STAKES
        elif med_matches >= 2:
            return ActionTier.T2_HIGH_STAKES
        elif med_matches >= 1:
            return ActionTier.T1_SENSITIVE
        else:
            return ActionTier.T0_ROUTINE

    def evaluate(self, evidence: EvidenceObject, ontology_salt: str) -> AuditorOutput:
        """
        Evaluate action and check for tier underreporting.
        """
        baseline_tier = self.estimate_baseline_tier(evidence)
        
        # Calculate what tier the agent is claiming (from their scores)
        agent_irr = 1.0 - (
            evidence.irreversibility.factors.temporal_reversibility *
            evidence.irreversibility.factors.informational_reversibility *
            evidence.irreversibility.factors.causal_reversibility
        ) ** (1/3)
        
        if agent_irr >= 0.70 or evidence.suffering_risk_estimate >= 0.70:
            agent_tier = ActionTier.T3_CATASTROPHIC
        elif agent_irr >= 0.30 or evidence.suffering_risk_estimate >= 0.30:
            agent_tier = ActionTier.T2_HIGH_STAKES
        elif agent_irr >= 0.10 or evidence.suffering_risk_estimate >= 0.10:
            agent_tier = ActionTier.T1_SENSITIVE
        else:
            agent_tier = ActionTier.T0_ROUTINE
        
        # SINCERITY CHECK: Is agent significantly underreporting?
        tier_gap = baseline_tier.value - agent_tier.value
        
        if tier_gap >= 2:
            # Severe underreporting (e.g., claiming T0 for T2+ action)
            objection = True
            severity = ObjectionSeverity.HIGH
            reasoning = (
                f"SINCERITY_VIOLATION: Entry-gate estimates {baseline_tier.name} but agent claims {agent_tier.name}. "
                f"Tier gap of {tier_gap} triggers mandatory sincerity review."
            )
            recommendation = AuditOutcome.ESCROW
            confidence = 0.85
        elif tier_gap >= 1:
            # Moderate underreporting
            objection = True
            severity = ObjectionSeverity.MEDIUM
            reasoning = (
                f"Entry-gate estimates {baseline_tier.name} but agent claims {agent_tier.name}. "
                f"Recommend elevated scrutiny."
            )
            recommendation = None
            confidence = 0.70
        else:
            # No significant underreporting
            objection = False
            severity = ObjectionSeverity.LOW
            reasoning = f"Entry-gate tier estimate ({baseline_tier.name}) aligns with agent claim ({agent_tier.name})."
            recommendation = None
            confidence = 0.60
        
        return AuditorOutput(
            self.auditor_id, self.role, recommendation, confidence,
            objection, severity, reasoning, ontology_salt
        )


# ---------------------------
# Irreversibility scoring
# ---------------------------

@dataclass(frozen=True)
class IrreversibilityScoringPolicy:
    """
    Policy for combining reversibility factors.

    Default uses geometric mean because:
    - If any axis is near-irreversible, the action is near-irreversible overall.
    - It discourages gaming by inflating one factor to compensate for another.

    You may override weights to reflect domain reality.
    
    ANTI-AVERAGING SAFEGUARD:
    The `catastrophic_floor` parameter prevents "averaging attacks" where an agent
    inflates one factor to mask a catastrophic score in another. If ANY factor
    falls below this floor, the action is automatically promoted to T3.
    """
    w_temporal: float = 1.0
    w_informational: float = 1.0
    w_causal: float = 1.0
    
    # Anti-averaging: If ANY factor is below this, auto-promote to T3
    # This prevents gaming by inflating irrelevant factors
    catastrophic_floor: float = 0.10  # Below 10% reversibility = catastrophic
    
    # Whether to enforce the catastrophic floor
    enforce_catastrophic_floor: bool = True

    def validate(self) -> List[str]:
        errors=[]
        for n,v in [("w_temporal", self.w_temporal), ("w_informational", self.w_informational), ("w_causal", self.w_causal)]:
            if v <= 0:
                errors.append(f"IrreversibilityScoringPolicy: {n} must be > 0")
        if not (0.0 <= self.catastrophic_floor <= 0.5):
            errors.append(f"IrreversibilityScoringPolicy: catastrophic_floor must be in [0, 0.5], got {self.catastrophic_floor}")
        return errors
    
    def check_catastrophic_floor(self, factors: IrreversibilityFactors) -> Tuple[bool, Optional[str]]:
        """
        Check if any factor falls below the catastrophic floor.
        
        Returns:
            (is_catastrophic, reason): True if any factor is below floor, with explanation
        """
        if not self.enforce_catastrophic_floor:
            return (False, None)
        
        floor = self.catastrophic_floor
        violations = []
        
        if factors.temporal_reversibility < floor:
            violations.append(f"temporal={factors.temporal_reversibility:.2f}")
        if factors.informational_reversibility < floor:
            violations.append(f"informational={factors.informational_reversibility:.2f}")
        if factors.causal_reversibility < floor:
            violations.append(f"causal={factors.causal_reversibility:.2f}")
        
        if violations:
            reason = f"CATASTROPHIC_FLOOR: factor(s) below {floor}: {', '.join(violations)}"
            return (True, reason)
        
        return (False, None)

def compute_irreversibility_score(assess: IrreversibilityAssessment, policy: IrreversibilityScoringPolicy) -> float:
    """
    Returns irreversibility in [0,1] where 1=highly irreversible.
    
    Uses weighted geometric mean on reversibility factors, with safeguards:
    - Tiny epsilon (1e-12) prevents numerical instability at exact zero
    - Does NOT use logarithms (geometric mean via exponentiation is stable)
    - Confidence-weighted adjustment reduces score certainty for low-confidence assessments
    
    HARDENING (v1.7.4):
    - Epsilon reduced from 0.01 to 1e-12 to prevent "safety smoothing" exploit
      where adversaries report near-zero values to get clamped upward
    - Catastrophic floor check (in IrreversibilityScoringPolicy) handles truly
      irreversible factors separately, so this function doesn't need a high floor
    """
    f = assess.factors
    
    # Tiny epsilon only for numerical stability at exact zero
    # This does NOT provide meaningful safety smoothing - that's handled by catastrophic_floor
    EPSILON = 1e-12
    
    t_rev = max(EPSILON, f.temporal_reversibility)
    i_rev = max(EPSILON, f.informational_reversibility)
    c_rev = max(EPSILON, f.causal_reversibility)
    
    # Weighted geometric mean on reversibility factors
    wsum = policy.w_temporal + policy.w_informational + policy.w_causal
    # HARDENING: guard against zero/negative weight sums (fail-closed)
    if wsum <= 0:
        return 1.0

    wt = policy.w_temporal / wsum
    wi = policy.w_informational / wsum
    wc = policy.w_causal / wsum
    
    rev = (t_rev ** wt) * (i_rev ** wi) * (c_rev ** wc)
    irr = 1.0 - rev
    
    # Confidence adjustment: lower confidence -> regression toward middle (0.5)
    # This prevents over-confident scores from low-quality assessments
    if assess.confidence < 1.0:
        regression_strength = 1.0 - assess.confidence
        irr = irr * assess.confidence + 0.5 * regression_strength * 0.3  # Partial regression
    
    return float(_clamp01(irr))

def infer_tier(irr: float, suffering_risk: float, catastrophic_override: bool = False,
               boundaries: Optional[TierBoundaries] = None) -> ActionTier:
    """
    Infer action tier from irreversibility and suffering risk.
    
    HARDENING (v1.9.0): Uses epsilon-safe float comparisons to prevent
    "edge case flips" where identical evidence produces different tiers
    on different hardware due to floating-point precision differences.
    
    Args:
        irr: Irreversibility score [0,1]
        suffering_risk: Suffering risk estimate [0,1]
        catastrophic_override: Force T3 classification
        boundaries: Optional custom tier boundaries (for drift testing)
    
    Returns:
        ActionTier classification
    """
    b = boundaries or DEFAULT_TIER_BOUNDARIES
    
    # HARDENING (v1.9.0): Use epsilon-safe comparisons
    if catastrophic_override or _float_ge(suffering_risk, b.suffering_t3_threshold):
        return ActionTier.T3_CATASTROPHIC
    if _float_lt(irr, b.t0_t1_boundary):
        return ActionTier.T0_ROUTINE
    if _float_lt(irr, b.t1_t2_boundary):
        return ActionTier.T1_SENSITIVE
    if _float_lt(irr, b.t2_t3_boundary):
        return ActionTier.T2_HIGH_STAKES
    return ActionTier.T3_CATASTROPHIC


def infer_tier_with_jitter(irr: float, suffering_risk: float, 
                           jitter_range: float = 0.05,
                           action_id: Optional[str] = None,
                           server_salt: Optional[str] = None) -> Tuple[ActionTier, TierBoundaries]:
    """
    Infer tier with deterministic boundary jitter for semantic drift testing.
    
    HARDENING (v1.7.7): Jitter is now DETERMINISTIC based on action_id.
    This prevents the "Reroll Exploit" where an agent spams the same action
    hoping for favorable random jitter.
    
    HARDENING (v1.7.8): Server-side salt prevents "Action ID Mining".
    Without the salt, an agent could test different action_id values to find
    one that produces favorable jitter.
    
    Args:
        irr: Irreversibility score [0,1]
        suffering_risk: Suffering risk [0,1]
        jitter_range: Amount of jitter as fraction
        action_id: Deterministic seed for jitter (REQUIRED for security)
        server_salt: Server-side secret salt (REQUIRED for production security)
        
    Returns:
        (tier, boundaries_used) for reproducibility
    """
    boundaries = DEFAULT_TIER_BOUNDARIES.with_jitter(
        jitter_range, 
        seed=action_id,
        server_salt=server_salt
    )
    tier = infer_tier(irr, suffering_risk, boundaries=boundaries)
    return (tier, boundaries)


# ---------------------------
# Escrow
# ---------------------------

@dataclass(frozen=True)
class EscrowPolicy:
    """
    Concrete escrow protocol (fixes 'escrow is vague').

    - Escrow has a maximum duration.
    - Escrow is periodically reevaluated, triggered by time or external request.
    - On expiry, default action is DENY (conservative), unless explicitly extended.
    """
    max_duration_seconds: int = 7 * 24 * 3600          # 7 days
    reevaluation_interval_seconds: int = 24 * 3600     # 1 day
    default_on_expiry: AuditOutcome = AuditOutcome.DENY


@dataclass
class EscrowEntry:
    evidence: EvidenceObject
    created_at_utc: str
    expires_at_utc: str
    next_reeval_at_utc: str
    reason: str
    status: str = "pending"  # pending / released / expired / denied

    def should_reevaluate(self, now: datetime.datetime) -> bool:
        """
        Check if escrow should be reevaluated.
        
        HARDENING (v1.7.4): Wraps timestamp parsing in try/except.
        On parse failure, returns True (fail closed = reevaluate now).
        """
        try:
            nra = datetime.datetime.fromisoformat(self.next_reeval_at_utc.replace("Z", "+00:00"))
            return now >= nra
        except (ValueError, AttributeError) as e:
            logger.warning(f"Failed to parse next_reeval_at_utc '{self.next_reeval_at_utc}': {e}. Treating as should_reevaluate=True (fail closed)")
            return True  # Fail closed: reevaluate if timestamp is corrupted

    def is_expired(self, now: datetime.datetime) -> bool:
        """
        Check if escrow has expired.
        
        HARDENING (v1.7.4): Wraps timestamp parsing in try/except.
        On parse failure, returns True (fail closed = treat as expired).
        """
        try:
            exp = datetime.datetime.fromisoformat(self.expires_at_utc.replace("Z", "+00:00"))
            return now >= exp
        except (ValueError, AttributeError) as e:
            logger.warning(f"Failed to parse expires_at_utc '{self.expires_at_utc}': {e}. Treating as expired=True (fail closed)")
            return True  # Fail closed: expire if timestamp is corrupted


# ---------------------------
# External Review
# ---------------------------

@dataclass(frozen=True)
class ExternalReviewRequest:
    """
    A request for external review of a T3 action.
    This captures the workflow state for escalated decisions.
    """
    action_id: str
    evidence: EvidenceObject
    requested_at_utc: str
    requested_by: str  # system identifier or user ID
    reason: str
    urgency: str = "normal"  # normal / high / critical
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExternalReviewResponse:
    """
    Response from external reviewer (human panel, oversight board, etc.)
    
    HARDENING (v1.7.7): Cryptographic signature required for T3 approvals.
    The signature must be verifiable against a known public key.
    
    HARDENING (v1.9.0): Signature now binds to evidence_hash to prevent
    approval reuse with different evidence payloads.
    """
    action_id: str
    reviewer_id: str
    reviewer_type: str  # "human_panel", "oversight_board", "designated_authority"
    decision: str  # "approve", "deny", "request_more_info", "escalate_further"
    confidence: float
    reasoning: str
    conditions: List[str] = field(default_factory=list)  # conditions for approval
    reviewed_at_utc: str = ""
    signature: str = ""  # HMAC-SHA256 signature (required for T3)
    signature_key_id: str = ""  # Identifier for the signing key
    evidence_hash: str = ""  # HARDENING (v1.9.0): Hash of evidence being approved
    
    def __post_init__(self):
        if not self.reviewed_at_utc:
            self.reviewed_at_utc = _now_utc().replace(microsecond=0).isoformat().replace("+00:00", "Z")
    
    def compute_signature_payload(self) -> bytes:
        """
        Return the canonical payload that should be signed.
        
        HARDENING (v1.9.0):
        - Uses length-prefixed encoding (prevents delimiter attacks)
        - Includes evidence_hash (binds approval to specific evidence)
        - Uses canonical float format (cross-platform determinism)
        """
        # Deterministic payload for signature
        payload_parts = [
            self.action_id,
            self.reviewer_id,
            self.reviewer_type,
            self.decision,
            f"{self.confidence:.8f}",  # Canonical float format
            self.reasoning,
            ",".join(sorted(self.conditions)),
            self.reviewed_at_utc,
            self.evidence_hash,  # CRITICAL: Bind to evidence
        ]
        # Use safe encoding (length-prefixed, not delimiter-joined)
        return _safe_hash_encode(payload_parts)
    
    def verify_signature(self, secret_key: bytes) -> bool:
        """
        Verify HMAC-SHA256 signature using provided secret key.
        
        HARDENING (v1.7.7): This prevents spoofing of external approvals.
        The secret key should be held by the external review system, not the agent.
        """
        import hmac
        if not self.signature:
            return False
        payload = self.compute_signature_payload()
        expected = hmac.new(secret_key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)
    
    @staticmethod
    def create_signed(action_id: str, reviewer_id: str, reviewer_type: str,
                     decision: str, confidence: float, reasoning: str,
                     secret_key: bytes, key_id: str,
                     evidence_hash: str = "",
                     conditions: Optional[List[str]] = None) -> "ExternalReviewResponse":
        """
        Create a signed external review response.
        
        This should be called by the external review system, not by agents.
        
        HARDENING (v1.9.0): evidence_hash is now required for binding approval
        to specific evidence payload.
        """
        import hmac
        response = ExternalReviewResponse(
            action_id=action_id,
            reviewer_id=reviewer_id,
            reviewer_type=reviewer_type,
            decision=decision,
            confidence=confidence,
            reasoning=reasoning,
            conditions=conditions or [],
            signature_key_id=key_id,
            evidence_hash=evidence_hash,
        )
        payload = response.compute_signature_payload()
        response.signature = hmac.new(secret_key, payload, hashlib.sha256).hexdigest()
        return response


# ---------------------------
# Evidence Size Limits (DoS Protection)
# ---------------------------

@dataclass(frozen=True)
class EvidenceSizeLimits:
    """
    HARDENING (v1.7.7): Size limits to prevent DoS via oversized payloads.
    """
    max_description_length: int = 10000  # 10KB
    max_action_id_length: int = 256
    max_reasoning_length: int = 50000  # 50KB per auditor
    max_alternatives: int = 20
    max_alternative_description_length: int = 5000
    max_embedding_dimensions: int = 4096
    max_attestations: int = 10
    max_conditions: int = 50
    max_provenance_size: int = 100000  # 100KB total for provenance dict
    
    def validate_evidence(self, evidence: "EvidenceObject") -> List[str]:
        """Validate evidence against size limits."""
        errors = []
        if len(evidence.description) > self.max_description_length:
            errors.append(f"description exceeds {self.max_description_length} chars")
        if len(evidence.action_id) > self.max_action_id_length:
            errors.append(f"action_id exceeds {self.max_action_id_length} chars")
        if len(evidence.alternatives) > self.max_alternatives:
            errors.append(f"alternatives exceeds {self.max_alternatives} items")
        for i, alt in enumerate(evidence.alternatives):
            if len(alt.description) > self.max_alternative_description_length:
                errors.append(f"alternative[{i}].description exceeds limit")
            if alt.semantic_embedding and len(alt.semantic_embedding) > self.max_embedding_dimensions:
                errors.append(f"alternative[{i}].semantic_embedding exceeds {self.max_embedding_dimensions} dimensions")
        if len(evidence.attestations) > self.max_attestations:
            errors.append(f"attestations exceeds {self.max_attestations} items")
        # Check provenance size
        try:
            prov_json = json.dumps(evidence.provenance)
            if len(prov_json) > self.max_provenance_size:
                errors.append(f"provenance exceeds {self.max_provenance_size} bytes")
        except (TypeError, ValueError):
            errors.append("provenance is not JSON-serializable")
        return errors


DEFAULT_SIZE_LIMITS = EvidenceSizeLimits()


# ---------------------------
# Persistence (SQLite + hash-chain)
# ---------------------------

class AuditStore(Protocol):
    """
    Protocol for audit storage backends.
    
    HARDENING (v1.7.5):
    - Explicit interface methods for all required operations
    - Optional atomic_append for stores that support it
    - last_hash() required for chain integrity
    - verify_chain() required for integrity checks
    
    HARDENING (v1.7.7):
    - has_external_approval() for store-side approval verification
    - record_external_approval() for secure approval storage
    
    Implementers MUST provide thread-safe implementations.
    """
    def append(self, record: "AuditRecord") -> None:
        """Append a record. Must be thread-safe."""
        ...
    
    def get_recent(self, limit: int = 50) -> List["AuditRecord"]:
        """Get recent records in reverse chronological order."""
        ...
    
    def last_hash(self) -> str:
        """Get the hash of the most recent record, or '0'*64 if empty."""
        ...
    
    def verify_chain(self) -> Tuple[bool, List[str]]:
        """Verify hash chain integrity. Returns (is_valid, error_messages)."""
        ...
    
    def supports_atomic_append(self) -> bool:
        """Return True if this store supports atomic append with chain verification."""
        return False
    
    def has_external_approval(self, action_id: str,
                               policy: Optional["PMIPolicy"] = None,
                               secret_keys: Optional[Dict[str, bytes]] = None,
                               current_evidence_hash: Optional[str] = None) -> Tuple[bool, Optional["ExternalReviewResponse"]]:
        """
        Check if action has a verified external approval in the store.
        
        HARDENING (v1.7.7): External approvals are stored separately from evidence,
        preventing agents from spoofing the external_review_approved flag.
        
        HARDENING (v1.9.0): Now accepts policy for signature verification and
        current_evidence_hash for approval binding verification.
        
        Args:
            action_id: Action to check approval for
            policy: Optional PMIPolicy for signature requirements
            secret_keys: Optional dict of {key_id: secret_key_bytes} for verification
            current_evidence_hash: Optional hash of current evidence to match against
        
        Returns: (has_approval, response_if_exists)
        """
        ...
    
    def record_external_approval(self, response: "ExternalReviewResponse",
                                  policy: Optional["PMIPolicy"] = None,
                                  secret_keys: Optional[Dict[str, bytes]] = None) -> bool:
        """
        Record an external approval. Should only be called by external review system.
        
        HARDENING (v1.9.0): Now accepts policy and secret_keys for signature verification.
        
        Returns: True if recorded successfully, False if duplicate or invalid.
        """
        ...
    
    def get_metadata(self, key: str) -> Optional[str]:
        """
        Get a metadata value by key.
        
        HARDENING (v1.9.0): Used for persisting protocol state across restarts.
        """
        return None
    
    def set_metadata(self, key: str, value: str) -> None:
        """
        Set a metadata value.
        
        HARDENING (v1.9.0): Used for persisting protocol state across restarts.
        """
        pass


@dataclass(frozen=True)
class AuditRecord:
    """
    Persisted record; hash is chained to previous hash (append-only).
    
    HARDENING (v1.7.3):
    - timestamp_ingested_utc: Trusted timestamp set by protocol (not agent-provided)
    - protocol_version: Ensures audit trail compatibility across versions
    """
    action_id: str
    timestamp_utc: str  # Agent-claimed timestamp (metadata only)
    timestamp_ingested_utc: str  # Trusted timestamp set by protocol at ingestion
    protocol_version: str  # Protocol version that created this record
    tier: str
    outcome: str
    reason: str
    evidence_json: str
    auditor_json: str
    prev_hash: str
    record_hash: str


class SQLiteAuditStore:
    """
    SQLite-based audit store with hash-chained integrity.
    
    HARDENING (v1.7.7):
    - WAL mode for concurrent reads during writes (reduces DoS vector)
    - External approvals table for non-spoofable T3 approvals
    - External anchoring support for tamper-evidence
    - Size limit enforcement
    """
    def __init__(self, path: str = "lattice_audit.db", 
                 enable_wal: bool = True,
                 size_limits: Optional["EvidenceSizeLimits"] = None):
        self.path = path
        self._lock = threading.RLock()
        self._enable_wal = enable_wal
        self._size_limits = size_limits or DEFAULT_SIZE_LIMITS
        self._init_db()

    def _init_db(self) -> None:
        with self._lock, sqlite3.connect(self.path) as conn:
            # HARDENING: Enable WAL mode for better concurrency
            # WAL allows concurrent reads during writes, reducing serialization bottleneck
            if self._enable_wal:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")  # Good performance with WAL
            
            # Main audit log with trusted timestamps and protocol version
            conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id TEXT NOT NULL,
                timestamp_utc TEXT NOT NULL,
                timestamp_ingested_utc TEXT NOT NULL,
                protocol_version TEXT NOT NULL,
                tier TEXT NOT NULL,
                outcome TEXT NOT NULL,
                reason TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                auditor_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL
            )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_action_id ON audit_log(action_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ingested ON audit_log(timestamp_ingested_utc)")
            
            # CHAIN HEAD TABLE: Atomic chain integrity
            # Single-row table for atomic check-and-set of chain head
            conn.execute("""
            CREATE TABLE IF NOT EXISTS chain_head (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_hash TEXT NOT NULL,
                last_id INTEGER NOT NULL,
                updated_at_utc TEXT NOT NULL
            )
            """)
            # Initialize chain head if not exists
            cur = conn.execute("SELECT COUNT(*) FROM chain_head")
            if cur.fetchone()[0] == 0:
                conn.execute("""
                INSERT INTO chain_head (id, last_hash, last_id, updated_at_utc)
                VALUES (1, ?, 0, ?)
                """, ("0"*64, _now_utc().isoformat()))
            
            # EXTERNAL APPROVALS TABLE (v1.7.7, updated v1.9.0)
            # Non-spoofable external review approvals stored separately from evidence
            conn.execute("""
            CREATE TABLE IF NOT EXISTS external_approvals (
                action_id TEXT PRIMARY KEY,
                reviewer_id TEXT NOT NULL,
                reviewer_type TEXT NOT NULL,
                decision TEXT NOT NULL,
                confidence REAL NOT NULL,
                reasoning TEXT NOT NULL,
                conditions TEXT NOT NULL,
                reviewed_at_utc TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_key_id TEXT NOT NULL,
                recorded_at_utc TEXT NOT NULL,
                evidence_hash TEXT DEFAULT ''
            )
            """)
            
            # PROTOCOL METADATA TABLE (v1.9.0)
            # Persisted state that must survive restarts
            conn.execute("""
            CREATE TABLE IF NOT EXISTS protocol_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            )
            """)
            
            # Migration: Add evidence_hash column if missing (for existing DBs)
            try:
                conn.execute("ALTER TABLE external_approvals ADD COLUMN evidence_hash TEXT DEFAULT ''")
            except sqlite3.OperationalError:
                pass  # Column already exists
            
            # EXTERNAL ANCHORS TABLE (v1.7.7)
            # Periodic snapshots of chain head for external tamper-evidence
            conn.execute("""
            CREATE TABLE IF NOT EXISTS external_anchors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                anchor_type TEXT NOT NULL,
                chain_head_hash TEXT NOT NULL,
                chain_length INTEGER NOT NULL,
                merkle_root TEXT,
                anchored_at_utc TEXT NOT NULL,
                external_reference TEXT,
                verified BOOLEAN DEFAULT FALSE
            )
            """)
            
            # Escrow persistence table (fixes volatility issue)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS escrow_queue (
                action_id TEXT PRIMARY KEY,
                evidence_json TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                expires_at_utc TEXT NOT NULL,
                next_reeval_at_utc TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
            )
            """)
            
            # Agent history tracking (for necessity inflation detection)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                timestamp_utc TEXT NOT NULL,
                tier TEXT NOT NULL,
                outcome TEXT NOT NULL,
                necessity_claimed REAL NOT NULL,
                irreversibility_score REAL NOT NULL
            )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_history_agent ON agent_history(agent_id)")
            
            # Action locks table (race condition protection)
            # Prevents "evidence shadowing" attacks where two submissions race
            conn.execute("""
            CREATE TABLE IF NOT EXISTS action_locks (
                action_id TEXT PRIMARY KEY,
                locked_at_utc TEXT NOT NULL,
                lock_holder TEXT NOT NULL,
                expires_at_utc TEXT NOT NULL
            )
            """)
            
            # Semantic cooldown table (rejection lockout)
            # HARDENING (v1.7.8): Added embedding column for semantic similarity checking
            conn.execute("""
            CREATE TABLE IF NOT EXISTS rejection_cooldowns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id TEXT NOT NULL,
                description_hash TEXT NOT NULL,
                description_text TEXT NOT NULL,
                embedding_json TEXT,
                rejected_at_utc TEXT NOT NULL,
                cooldown_expires_utc TEXT NOT NULL,
                reason TEXT NOT NULL
            )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cooldown_hash ON rejection_cooldowns(description_hash)")
            
            # Telemetry verification table (v1.7.8)
            # For cross-examination of agent-provided evidence
            conn.execute("""
            CREATE TABLE IF NOT EXISTS telemetry_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id TEXT NOT NULL,
                source_id TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                measured_value REAL NOT NULL,
                claimed_value REAL,
                deviation REAL,
                recorded_at_utc TEXT NOT NULL,
                verified BOOLEAN DEFAULT FALSE
            )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_action ON telemetry_records(action_id)")
            
            # Verified provider attestations (v1.7.8)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS provider_attestations (
                provider_id TEXT PRIMARY KEY,
                public_key_hash TEXT NOT NULL,
                attestation_signature TEXT NOT NULL,
                attested_at_utc TEXT NOT NULL,
                expires_at_utc TEXT,
                verified BOOLEAN DEFAULT FALSE
            )
            """)
            
            conn.commit()
    
    # ---------------------------
    # External Approval Methods (v1.7.7)
    # ---------------------------
    
    def has_external_approval(self, action_id: str, 
                               policy: Optional["PMIPolicy"] = None,
                               secret_keys: Optional[Dict[str, bytes]] = None,
                               current_evidence_hash: Optional[str] = None) -> Tuple[bool, Optional["ExternalReviewResponse"]]:
        """
        Check if action has a verified external approval in the store.
        
        HARDENING (v1.7.7): External approvals are stored separately from evidence,
        preventing agents from spoofing the external_review_approved flag.
        
        HARDENING (v1.8.0): Signature verification is now enforced when
        require_signed_external_approvals=True in policy.
        
        HARDENING (v1.9.0): Evidence hash binding ensures approval is for
        the current evidence payload, not a different one.
        
        Args:
            action_id: Action to check approval for
            policy: PMIPolicy for signature requirements
            secret_keys: Dict of {key_id: secret_key_bytes} for verification
            current_evidence_hash: Hash of current evidence to match against approval
        """
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute("""
            SELECT reviewer_id, reviewer_type, decision, confidence, reasoning,
                   conditions, reviewed_at_utc, signature, signature_key_id, evidence_hash
            FROM external_approvals WHERE action_id = ? AND decision = 'approve'
            """, (action_id,))
            row = cur.fetchone()
        
        if not row:
            return (False, None)
        
        response = ExternalReviewResponse(
            action_id=action_id,
            reviewer_id=row[0],
            reviewer_type=row[1],
            decision=row[2],
            confidence=row[3],
            reasoning=row[4],
            conditions=json.loads(row[5]) if row[5] else [],
            reviewed_at_utc=row[6],
            signature=row[7],
            signature_key_id=row[8],
            evidence_hash=row[9] if len(row) > 9 and row[9] else "",
        )
        
        # HARDENING (v1.9.0): Verify evidence hash matches if provided
        if current_evidence_hash and response.evidence_hash:
            if response.evidence_hash != current_evidence_hash:
                logger.error(
                    f"EVIDENCE_HASH_MISMATCH: External approval for {action_id} was for "
                    f"evidence_hash {response.evidence_hash[:16]}... but current evidence is "
                    f"{current_evidence_hash[:16]}... - approval not valid for this evidence."
                )
                return (False, None)
        
        # HARDENING (v1.8.0): Verify signature on read (defense in depth)
        if policy is not None and policy.require_signed_external_approvals:
            if not response.signature or not response.signature_key_id:
                logger.warning(
                    f"External approval for {action_id} has no signature but policy requires signed approvals"
                )
                return (False, None)
            
            # Check if key_id is in trusted list
            if policy.trusted_reviewer_key_ids and response.signature_key_id not in policy.trusted_reviewer_key_ids:
                logger.warning(
                    f"External approval for {action_id} signed with untrusted key '{response.signature_key_id}'"
                )
                return (False, None)
            
            # HARDENING (v1.8.1): FAIL-CLOSED when signature verification required but keys unavailable
            # If require_signed_external_approvals=True, we MUST actually verify, not just check presence
            if secret_keys is None:
                logger.error(
                    f"SIGNATURE_VERIFICATION_IMPOSSIBLE: External approval for {action_id} requires "
                    "signature verification but no secret_keys provided. FAIL-CLOSED."
                )
                return (False, None)
            
            # Verify signature
            key = secret_keys.get(response.signature_key_id)
            if key is None:
                logger.error(
                    f"SIGNATURE_VERIFICATION_FAILED: No secret key available for key_id "
                    f"'{response.signature_key_id}' - cannot verify. FAIL-CLOSED."
                )
                return (False, None)
            if not response.verify_signature(key):
                logger.error(
                    f"SIGNATURE_VERIFICATION_FAILED: External approval for {action_id} has invalid signature"
                )
                return (False, None)
        
        return (True, response)
    
    def record_external_approval(self, response: "ExternalReviewResponse",
                                  policy: Optional["PMIPolicy"] = None,
                                  secret_keys: Optional[Dict[str, bytes]] = None) -> bool:
        """
        Record an external approval. Should only be called by external review system.
        
        HARDENING (v1.7.7): Requires valid signature for T3-capable approvals.
        
        HARDENING (v1.8.0): Signature verification is now enforced on INSERT
        when require_signed_external_approvals=True.
        
        Args:
            response: External review response to record
            policy: PMIPolicy for signature requirements
            secret_keys: Dict of {key_id: secret_key_bytes} for verification
            
        Returns:
            True if recorded successfully, False if rejected or duplicate
        """
        # HARDENING (v1.8.0): Verify signature on insert
        if policy is not None and policy.require_signed_external_approvals:
            if not response.signature or not response.signature_key_id:
                logger.error(
                    f"Cannot record unsigned external approval for {response.action_id} - policy requires signatures"
                )
                return False
            
            # Check trusted key IDs
            if policy.trusted_reviewer_key_ids and response.signature_key_id not in policy.trusted_reviewer_key_ids:
                logger.error(
                    f"Cannot record external approval for {response.action_id} - "
                    f"key_id '{response.signature_key_id}' not in trusted list"
                )
                return False
            
            # Verify signature
            if secret_keys is not None:
                key = secret_keys.get(response.signature_key_id)
                if key is None:
                    logger.error(
                        f"Cannot verify external approval for {response.action_id} - "
                        f"no secret key for key_id '{response.signature_key_id}'"
                    )
                    return False
                if not response.verify_signature(key):
                    logger.error(
                        f"SIGNATURE_VERIFICATION_FAILED: Rejecting external approval for {response.action_id}"
                    )
                    return False
        
        with self._lock, sqlite3.connect(self.path) as conn:
            try:
                conn.execute("""
                INSERT INTO external_approvals 
                (action_id, reviewer_id, reviewer_type, decision, confidence, reasoning,
                 conditions, reviewed_at_utc, signature, signature_key_id, recorded_at_utc, evidence_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    response.action_id, response.reviewer_id, response.reviewer_type,
                    response.decision, response.confidence, response.reasoning,
                    json.dumps(response.conditions), response.reviewed_at_utc,
                    response.signature, response.signature_key_id,
                    _now_utc().isoformat(),
                    response.evidence_hash or ""
                ))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False  # Duplicate
    
    # ---------------------------
    # Protocol Metadata Methods (v1.9.0)
    # ---------------------------
    
    def get_metadata(self, key: str) -> Optional[str]:
        """
        Get a metadata value by key.
        
        HARDENING (v1.9.0): Used for persisting protocol state across restarts
        (e.g., fast-path streak counter, last anchor time).
        """
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute(
                "SELECT value FROM protocol_metadata WHERE key = ?",
                (key,)
            )
            row = cur.fetchone()
            return row[0] if row else None
    
    def set_metadata(self, key: str, value: str) -> None:
        """
        Set a metadata value.
        
        HARDENING (v1.9.0): Used for persisting protocol state across restarts.
        """
        with self._lock, sqlite3.connect(self.path) as conn:
            conn.execute("""
            INSERT OR REPLACE INTO protocol_metadata (key, value, updated_at_utc)
            VALUES (?, ?, ?)
            """, (key, value, _now_utc().isoformat()))
            conn.commit()
    
    def increment_metadata(self, key: str, default: int = 0) -> int:
        """
        Atomically increment a metadata counter.
        
        Returns the new value.
        """
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute(
                "SELECT value FROM protocol_metadata WHERE key = ?",
                (key,)
            )
            row = cur.fetchone()
            current = int(row[0]) if row else default
            new_value = current + 1
            conn.execute("""
            INSERT OR REPLACE INTO protocol_metadata (key, value, updated_at_utc)
            VALUES (?, ?, ?)
            """, (key, str(new_value), _now_utc().isoformat()))
            conn.commit()
            return new_value
    
    # ---------------------------
    # External Anchoring Methods (v1.7.7)
    # ---------------------------
    
    def create_anchor(self, anchor_type: str = "periodic",
                     external_reference: Optional[str] = None) -> Dict[str, Any]:
        """
        Create an external anchor snapshot of the current chain state.
        
        This can be written to external systems (HSM, blockchain, append-only log)
        to provide tamper-evidence against full database replacement.
        
        Returns dict with anchor details for external storage.
        """
        with self._lock, sqlite3.connect(self.path) as conn:
            # Get current chain head
            cur = conn.execute("SELECT last_hash, last_id FROM chain_head WHERE id = 1")
            head_row = cur.fetchone()
            head_hash = head_row[0] if head_row else "0"*64
            chain_length = head_row[1] if head_row else 0
            
            # Compute Merkle root of all record hashes (optional, for full verification)
            cur = conn.execute("SELECT record_hash FROM audit_log ORDER BY id")
            hashes = [row[0] for row in cur.fetchall()]
            merkle_root = self._compute_merkle_root(hashes) if hashes else "0"*64
            
            anchor_time = _now_utc().isoformat()
            
            # Store anchor locally
            conn.execute("""
            INSERT INTO external_anchors 
            (anchor_type, chain_head_hash, chain_length, merkle_root, anchored_at_utc, external_reference)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (anchor_type, head_hash, chain_length, merkle_root, anchor_time, external_reference))
            conn.commit()
            
            return {
                "anchor_type": anchor_type,
                "chain_head_hash": head_hash,
                "chain_length": chain_length,
                "merkle_root": merkle_root,
                "anchored_at_utc": anchor_time,
                "external_reference": external_reference,
            }
    
    def _compute_merkle_root(self, hashes: List[str]) -> str:
        """Compute Merkle root of hash list."""
        if not hashes:
            return "0"*64
        if len(hashes) == 1:
            return hashes[0]
        
        # Pad to even length
        if len(hashes) % 2 == 1:
            hashes = hashes + [hashes[-1]]
        
        # Compute parent level
        parents = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i+1]
            parents.append(_sha256_hex(combined.encode('utf-8')))
        
        return self._compute_merkle_root(parents)
    
    def verify_anchor(self, anchor: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Verify that current chain state matches an external anchor.
        
        Returns (matches, reason).
        """
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute("SELECT last_hash, last_id FROM chain_head WHERE id = 1")
            head_row = cur.fetchone()
            current_hash = head_row[0] if head_row else "0"*64
            current_length = head_row[1] if head_row else 0
        
        if current_hash != anchor.get("chain_head_hash"):
            return (False, f"Chain head mismatch: expected {anchor.get('chain_head_hash')[:16]}..., got {current_hash[:16]}...")
        
        if current_length < anchor.get("chain_length", 0):
            return (False, f"Chain length decreased: expected >= {anchor.get('chain_length')}, got {current_length}")
        
        return (True, "Anchor verified")

    def _get_last_hash(self, conn) -> str:
        """Get last hash from chain_head table (atomic)."""
        cur = conn.execute("SELECT last_hash FROM chain_head WHERE id = 1")
        row = cur.fetchone()
        return row[0] if row else "0"*64
    
    def _atomic_append(self, conn, record: "AuditRecord") -> bool:
        """
        Atomic append with chain head verification.
        
        Uses EXCLUSIVE transaction to ensure no concurrent modifications.
        Returns True if append succeeded, False if chain head mismatch.
        """
        # Start exclusive transaction
        conn.execute("BEGIN EXCLUSIVE")
        try:
            # Verify chain head matches
            cur = conn.execute("SELECT last_hash, last_id FROM chain_head WHERE id = 1")
            head_row = cur.fetchone()
            expected_prev = head_row[0] if head_row else "0"*64
            
            if record.prev_hash != expected_prev:
                conn.execute("ROLLBACK")
                return False
            
            # Insert record
            conn.execute("""
            INSERT INTO audit_log (
                action_id, timestamp_utc, timestamp_ingested_utc, protocol_version,
                tier, outcome, reason, evidence_json, auditor_json, prev_hash, record_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.action_id, record.timestamp_utc, record.timestamp_ingested_utc,
                record.protocol_version, record.tier, record.outcome, record.reason,
                record.evidence_json, record.auditor_json, record.prev_hash, record.record_hash
            ))
            
            new_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            
            # Update chain head
            conn.execute("""
            UPDATE chain_head SET last_hash = ?, last_id = ?, updated_at_utc = ? WHERE id = 1
            """, (record.record_hash, new_id, _now_utc().isoformat()))
            
            conn.execute("COMMIT")
            return True
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def check_evidence_consistency(self, action_id: str, evidence_hash: str) -> Tuple[bool, Optional[str]]:
        """
        Check if action_id was previously submitted with different evidence.
        
        Returns:
            (is_consistent, existing_hash): True if no conflict, existing hash if conflict exists
        """
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute("""
            SELECT evidence_json FROM audit_log WHERE action_id = ? ORDER BY id ASC LIMIT 1
            """, (action_id,))
            row = cur.fetchone()
            if row is None:
                return (True, None)  # No previous record, consistent
            existing_evidence_hash = _sha256_hex(row[0].encode('utf-8'))
            if existing_evidence_hash == evidence_hash:
                return (True, existing_evidence_hash)  # Same evidence, consistent
            return (False, existing_evidence_hash)  # Different evidence - CONFLICT

    # ---------------------------
    # Action Lock Methods (Race Condition Protection)
    # ---------------------------
    
    def acquire_action_lock(self, action_id: str, lock_holder: str = "default",
                            timeout_seconds: int = 30) -> Tuple[bool, Optional[str]]:
        """
        Acquire an exclusive lock on an action_id.
        
        This prevents "evidence shadowing" attacks where two submissions race.
        
        Args:
            action_id: The action to lock
            lock_holder: Identifier for the lock holder (for debugging)
            timeout_seconds: How long the lock is valid
            
        Returns:
            (acquired, reason): True if lock acquired, reason if not
        """
        now = _now_utc()
        expires = now + datetime.timedelta(seconds=timeout_seconds)
        now_str = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        expires_str = expires.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        
        with self._lock, sqlite3.connect(self.path) as conn:
            # Use EXCLUSIVE transaction for atomic check-and-set
            conn.execute("BEGIN EXCLUSIVE")
            try:
                # Check for existing lock
                cur = conn.execute("""
                SELECT lock_holder, expires_at_utc FROM action_locks WHERE action_id = ?
                """, (action_id,))
                row = cur.fetchone()
                
                if row:
                    existing_holder, existing_expires = row
                    expires_dt = datetime.datetime.fromisoformat(existing_expires.replace("Z", "+00:00"))
                    
                    if expires_dt > now:
                        # Lock is still valid
                        conn.rollback()
                        return (False, f"Action locked by {existing_holder} until {existing_expires}")
                    else:
                        # Lock expired, delete it
                        conn.execute("DELETE FROM action_locks WHERE action_id = ?", (action_id,))
                
                # Acquire the lock
                conn.execute("""
                INSERT INTO action_locks (action_id, locked_at_utc, lock_holder, expires_at_utc)
                VALUES (?, ?, ?, ?)
                """, (action_id, now_str, lock_holder, expires_str))
                
                conn.commit()
                return (True, None)
                
            except Exception as e:
                conn.rollback()
                return (False, f"Lock acquisition failed: {e}")
    
    def release_action_lock(self, action_id: str, lock_holder: str = "default") -> bool:
        """
        Release a lock on an action_id.
        
        Args:
            action_id: The action to unlock
            lock_holder: Must match the holder who acquired the lock
            
        Returns:
            True if released, False if lock didn't exist or wasn't held by this holder
        """
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute("""
            DELETE FROM action_locks WHERE action_id = ? AND lock_holder = ?
            """, (action_id, lock_holder))
            conn.commit()
            return cur.rowcount > 0
    
    def cleanup_expired_locks(self) -> int:
        """Remove all expired locks. Returns count of locks removed."""
        now_str = _now_utc().replace(microsecond=0).isoformat().replace("+00:00", "Z")
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute("""
            DELETE FROM action_locks WHERE expires_at_utc < ?
            """, (now_str,))
            conn.commit()
            return cur.rowcount

    def append(self, record: AuditRecord) -> None:
        """
        Append a record to the audit log with atomic chain head update.
        
        HARDENING: Uses atomic check-and-set to prevent chain forks under concurrency.
        If chain head doesn't match expected prev_hash, raises an exception.
        """
        with self._lock, sqlite3.connect(self.path) as conn:
            if not self._atomic_append(conn, record):
                raise RuntimeError(
                    f"Chain head mismatch: expected prev_hash {record.prev_hash[:16]}... "
                    f"but chain head has changed. This may indicate concurrent writes."
                )

    def get_recent(self, limit: int = 50) -> List[AuditRecord]:
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute("""
            SELECT action_id, timestamp_utc, timestamp_ingested_utc, protocol_version,
                   tier, outcome, reason, evidence_json, auditor_json, prev_hash, record_hash
            FROM audit_log ORDER BY id DESC LIMIT ?
            """, (int(limit),))
            rows = cur.fetchall()
        return [AuditRecord(*r) for r in rows]

    def last_hash(self) -> str:
        with self._lock, sqlite3.connect(self.path) as conn:
            return self._get_last_hash(conn)

    def get_all(self) -> List[AuditRecord]:
        """Retrieve all records in chronological order (oldest first)."""
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute("""
            SELECT action_id, timestamp_utc, timestamp_ingested_utc, protocol_version,
                   tier, outcome, reason, evidence_json, auditor_json, prev_hash, record_hash
            FROM audit_log ORDER BY id ASC
            """)
            rows = cur.fetchall()
        return [AuditRecord(*r) for r in rows]

    def get_by_action_id(self, action_id: str) -> List[AuditRecord]:
        """Retrieve all records for a specific action_id."""
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute("""
            SELECT action_id, timestamp_utc, timestamp_ingested_utc, protocol_version,
                   tier, outcome, reason, evidence_json, auditor_json, prev_hash, record_hash
            FROM audit_log WHERE action_id = ? ORDER BY id ASC
            """, (action_id,))
            rows = cur.fetchall()
        return [AuditRecord(*r) for r in rows]

    def count(self) -> int:
        """Return total number of records."""
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute("SELECT COUNT(*) FROM audit_log")
            return cur.fetchone()[0]

    def verify_chain(self) -> Tuple[bool, List[str]]:
        """
        Verify the integrity of the hash chain.
        
        Returns:
            (is_valid, errors): Tuple of validity bool and list of error messages.
            
        This checks:
        1. Each record's prev_hash matches the previous record's record_hash
        2. First record's prev_hash is all zeros
        3. No gaps or reordering detected
        """
        errors: List[str] = []
        records = self.get_all()
        
        if not records:
            return (True, [])
        
        # First record should have prev_hash of all zeros
        if records[0].prev_hash != "0" * 64:
            errors.append(f"Record 0: First record prev_hash should be all zeros, got {records[0].prev_hash[:16]}...")
        
        # Check chain continuity
        for i in range(1, len(records)):
            expected_prev = records[i-1].record_hash
            actual_prev = records[i].prev_hash
            if expected_prev != actual_prev:
                errors.append(
                    f"Record {i}: Chain broken. Expected prev_hash={expected_prev[:16]}..., "
                    f"got {actual_prev[:16]}..."
                )
        
        return (len(errors) == 0, errors)

    def recompute_and_verify(self) -> Tuple[bool, List[str]]:
        """
        Recompute hashes and verify they match stored values.
        
        This is a stronger check that detects if record content was modified.
        
        HARDENING (v1.7.6): Hash now includes all critical fields:
        - prev_hash, protocol_version, action_id
        - timestamp_utc, timestamp_ingested_utc
        - evidence_json, auditor_json
        - outcome, reason, tier
        
        HARDENING (v1.8.0): Uses length-prefixed encoding to prevent delimiter attacks.
        
        For backward compatibility with older records, we try multiple formats.
        """
        errors: List[str] = []
        records = self.get_all()
        
        if not records:
            return (True, [])
        
        prev_hash = "0" * 64
        for i, rec in enumerate(records):
            hash_components = [
                prev_hash,
                rec.protocol_version,
                rec.action_id,
                rec.timestamp_utc,
                rec.timestamp_ingested_utc,
                rec.evidence_json,
                rec.auditor_json,
                rec.outcome,
                rec.reason,
                rec.tier,
            ]
            
            # v1.8.0 format: length-prefixed encoding (secure)
            expected_hash_v180 = _sha256_hex(_safe_hash_encode(hash_components))
            
            # v1.7.6/v1.7.9 format: "||" delimiter (backward compat)
            expected_hash_v176 = _sha256_hex(_legacy_hash_encode(hash_components))
            
            # v1.7.5 format (even older backward compat)
            core_v175 = (prev_hash + rec.protocol_version + rec.evidence_json + rec.outcome + rec.reason + rec.tier).encode("utf-8")
            expected_hash_v175 = _sha256_hex(core_v175)
            
            hash_matches = rec.record_hash in (expected_hash_v180, expected_hash_v176, expected_hash_v175)
            
            if not hash_matches:
                errors.append(
                    f"Record {i} (action={rec.action_id}): Hash mismatch. "
                    f"Stored={rec.record_hash[:16]}..., Expected(v1.8.0)={expected_hash_v180[:16]}..."
                )
            
            if rec.prev_hash != prev_hash:
                errors.append(
                    f"Record {i} (action={rec.action_id}): prev_hash mismatch. "
                    f"Expected={prev_hash[:16]}..., Stored={rec.prev_hash[:16]}..."
                )
            
            prev_hash = rec.record_hash
        
        return (len(errors) == 0, errors)

    # ---------------------------
    # Escrow Persistence Methods
    # ---------------------------
    
    def save_escrow(self, action_id: str, entry: "EscrowEntry") -> None:
        """Persist an escrow entry to the database."""
        evidence_json = _canonical_json(entry.evidence.canonical_dict())
        with self._lock, sqlite3.connect(self.path) as conn:
            conn.execute("""
            INSERT OR REPLACE INTO escrow_queue 
            (action_id, evidence_json, created_at_utc, expires_at_utc, next_reeval_at_utc, reason, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (action_id, evidence_json, entry.created_at_utc, entry.expires_at_utc, 
                  entry.next_reeval_at_utc, entry.reason, entry.status))
            conn.commit()
    
    def load_escrow(self, action_id: str) -> Optional["EscrowEntry"]:
        """Load a single escrow entry from the database."""
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute("""
            SELECT evidence_json, created_at_utc, expires_at_utc, next_reeval_at_utc, reason, status
            FROM escrow_queue WHERE action_id = ?
            """, (action_id,))
            row = cur.fetchone()
        if not row:
            return None
        evidence = _parse_evidence_from_json(json.loads(row[0]))
        return EscrowEntry(
            evidence=evidence,
            created_at_utc=row[1],
            expires_at_utc=row[2],
            next_reeval_at_utc=row[3],
            reason=row[4],
            status=row[5],
        )
    
    def load_all_escrow(self) -> Dict[str, "EscrowEntry"]:
        """Load all pending escrow entries from the database."""
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute("""
            SELECT action_id, evidence_json, created_at_utc, expires_at_utc, next_reeval_at_utc, reason, status
            FROM escrow_queue WHERE status = 'pending'
            """)
            rows = cur.fetchall()
        result = {}
        for row in rows:
            try:
                evidence = _parse_evidence_from_json(json.loads(row[1]))
                result[row[0]] = EscrowEntry(
                    evidence=evidence,
                    created_at_utc=row[2],
                    expires_at_utc=row[3],
                    next_reeval_at_utc=row[4],
                    reason=row[5],
                    status=row[6],
                )
            except Exception as e:
                logger.warning(f"Failed to load escrow {row[0]}: {e}")
        return result
    
    def update_escrow_status(self, action_id: str, status: str) -> None:
        """Update the status of an escrow entry."""
        with self._lock, sqlite3.connect(self.path) as conn:
            conn.execute("""
            UPDATE escrow_queue SET status = ? WHERE action_id = ?
            """, (status, action_id))
            conn.commit()
    
    def delete_escrow(self, action_id: str) -> None:
        """Remove an escrow entry from the database."""
        with self._lock, sqlite3.connect(self.path) as conn:
            conn.execute("DELETE FROM escrow_queue WHERE action_id = ?", (action_id,))
            conn.commit()
    
    # ---------------------------
    # Agent History Tracking (Necessity Inflation Detection)
    # ---------------------------
    
    def record_agent_action(self, agent_id: str, action_id: str, tier: str,
                           outcome: str, necessity: float, irr: float) -> None:
        """Record an action for agent history tracking."""
        timestamp = _now_utc().replace(microsecond=0).isoformat().replace("+00:00", "Z")
        with self._lock, sqlite3.connect(self.path) as conn:
            conn.execute("""
            INSERT INTO agent_history 
            (agent_id, action_id, timestamp_utc, tier, outcome, necessity_claimed, irreversibility_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (agent_id, action_id, timestamp, tier, outcome, necessity, irr))
            conn.commit()
    
    def get_agent_history(self, agent_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent action history for an agent."""
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute("""
            SELECT action_id, timestamp_utc, tier, outcome, necessity_claimed, irreversibility_score
            FROM agent_history WHERE agent_id = ? ORDER BY id DESC LIMIT ?
            """, (agent_id, limit))
            rows = cur.fetchall()
        return [
            {
                "action_id": r[0], "timestamp": r[1], "tier": r[2],
                "outcome": r[3], "necessity": r[4], "irr": r[5]
            }
            for r in rows
        ]
    
    def detect_necessity_inflation(self, agent_id: str, window: int = 20,
                                   threshold: float = 0.7) -> Tuple[bool, Dict[str, Any]]:
        """
        Detect if an agent is inflating necessity claims.
        
        An agent is flagged if:
        - It has made at least `window` actions
        - A high percentage of high-necessity (>0.8), high-irr (>0.5) actions were denied/escrowed
        
        Returns:
            (is_flagged, stats): Whether agent is flagged and supporting statistics
        """
        history = self.get_agent_history(agent_id, window)
        if len(history) < window // 2:
            return (False, {"reason": "insufficient_history", "count": len(history)})
        
        high_stakes_actions = [
            h for h in history 
            if h["necessity"] > 0.8 and h["irr"] > 0.5
        ]
        
        if len(high_stakes_actions) < 3:
            return (False, {"reason": "few_high_stakes", "count": len(high_stakes_actions)})
        
        denied_or_escrowed = [
            h for h in high_stakes_actions
            if h["outcome"] in ("deny", "escrow", "require_external_review")
        ]
        
        denial_rate = len(denied_or_escrowed) / len(high_stakes_actions)
        
        stats = {
            "total_actions": len(history),
            "high_stakes_actions": len(high_stakes_actions),
            "denied_or_escrowed": len(denied_or_escrowed),
            "denial_rate": denial_rate,
            "threshold": threshold,
        }
        
        return (denial_rate >= threshold, stats)
    
    # ---------------------------
    # Rejection Cooldown (Semantic Similarity Protection)
    # ---------------------------
    
    def record_rejection_cooldown(self, action_id: str, description: str, 
                                   reason: str, cooldown_seconds: int = 3600,
                                   embedding: Optional[List[float]] = None) -> None:
        """
        Record a rejection for semantic cooldown checking.
        
        HARDENING: Prevents rapid resubmission of semantically similar actions
        after rejection (rejection lockout).
        
        HARDENING (v1.7.8): Now stores embeddings for semantic similarity checking.
        """
        now = _now_utc()
        expires = now + datetime.timedelta(seconds=cooldown_seconds)
        now_str = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        expires_str = expires.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        
        # Simple hash of description for exact-match lookup
        desc_hash = _sha256_hex(description.lower().strip().encode('utf-8'))[:32]
        
        # Store embedding as JSON if provided
        embedding_json = json.dumps(embedding) if embedding else None
        
        with self._lock, sqlite3.connect(self.path) as conn:
            conn.execute("""
            INSERT INTO rejection_cooldowns 
            (action_id, description_hash, description_text, embedding_json, 
             rejected_at_utc, cooldown_expires_utc, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (action_id, desc_hash, description[:1000], embedding_json, 
                  now_str, expires_str, reason))
            conn.commit()
    
    def check_rejection_cooldown(self, description: str, 
                                  embedding: Optional[List[float]] = None,
                                  similarity_threshold: float = 0.85) -> Tuple[bool, Optional[str]]:
        """
        Check if a similar action is under rejection cooldown.
        
        HARDENING (v1.7.8): Now supports semantic similarity via embeddings.
        If embedding is provided and stored embeddings exist, uses cosine similarity.
        Falls back to exact hash match if embeddings unavailable.
        
        Args:
            description: Action description to check
            embedding: Optional semantic embedding for similarity checking
            similarity_threshold: Cosine similarity threshold (0.0-1.0)
            
        Returns:
            (is_blocked, reason): True if blocked, with reason explaining why
        """
        now_str = _now_utc().replace(microsecond=0).isoformat().replace("+00:00", "Z")
        desc_hash = _sha256_hex(description.lower().strip().encode('utf-8'))[:32]
        
        with self._lock, sqlite3.connect(self.path) as conn:
            # First check exact hash match (fast path)
            cur = conn.execute("""
            SELECT action_id, reason, cooldown_expires_utc 
            FROM rejection_cooldowns 
            WHERE description_hash = ? AND cooldown_expires_utc > ?
            ORDER BY rejected_at_utc DESC LIMIT 1
            """, (desc_hash, now_str))
            row = cur.fetchone()
            
            if row:
                return (True, f"REJECTION_COOLDOWN: Exact match to denied action {row[0]}. "
                             f"Cooldown expires {row[2]}. Original reason: {row[1][:50]}...")
            
            # If embedding provided, check semantic similarity
            if embedding is not None:
                cur = conn.execute("""
                SELECT action_id, reason, cooldown_expires_utc, embedding_json, description_text
                FROM rejection_cooldowns 
                WHERE cooldown_expires_utc > ? AND embedding_json IS NOT NULL
                ORDER BY rejected_at_utc DESC
                """, (now_str,))
                
                for row in cur.fetchall():
                    stored_action_id, stored_reason, expires, stored_emb_json, stored_desc = row
                    try:
                        stored_embedding = json.loads(stored_emb_json)
                        similarity = self._cosine_similarity(embedding, stored_embedding)
                        
                        if similarity >= similarity_threshold:
                            return (True, 
                                f"SEMANTIC_COOLDOWN: Action is {similarity:.1%} similar to denied action "
                                f"{stored_action_id} ('{stored_desc[:30]}...'). "
                                f"Cooldown expires {expires}. Original reason: {stored_reason[:50]}..."
                            )
                    except (json.JSONDecodeError, TypeError):
                        continue
        
        return (False, None)
    
    def _cosine_similarity(self, vec_a: List[float], vec_b: List[float]) -> float:
        """
        Compute cosine similarity between two vectors.
        
        Returns value in [0, 1] where 1 means identical direction.
        """
        if len(vec_a) != len(vec_b) or len(vec_a) == 0:
            return 0.0
        
        dot_product = sum(a * b for a, b in zip(vec_a, vec_b))
        norm_a = sum(a * a for a in vec_a) ** 0.5
        norm_b = sum(b * b for b in vec_b) ** 0.5
        
        if norm_a == 0 or norm_b == 0:
            return 0.0
        
        return dot_product / (norm_a * norm_b)
    
    def cleanup_expired_cooldowns(self) -> int:
        """Remove expired cooldown entries. Returns count removed."""
        now_str = _now_utc().replace(microsecond=0).isoformat().replace("+00:00", "Z")
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute("""
            DELETE FROM rejection_cooldowns WHERE cooldown_expires_utc < ?
            """, (now_str,))
            conn.commit()
            return cur.rowcount
    
    # ---------------------------
    # CROSS-EXAMINATION / TELEMETRY (v1.7.8)
    # ---------------------------
    
    def record_telemetry(self, action_id: str, source_id: str, 
                         metric_name: str, measured_value: float,
                         claimed_value: Optional[float] = None) -> None:
        """
        Record telemetry measurement for cross-examination.
        
        HARDENING (v1.7.8): External telemetry sources can record their
        measurements independently, enabling verification of agent claims.
        """
        now_str = _now_utc().replace(microsecond=0).isoformat().replace("+00:00", "Z")
        deviation = None
        if claimed_value is not None and claimed_value != 0:
            deviation = abs(measured_value - claimed_value) / abs(claimed_value)
        
        with self._lock, sqlite3.connect(self.path) as conn:
            conn.execute("""
            INSERT INTO telemetry_records 
            (action_id, source_id, metric_name, measured_value, claimed_value, 
             deviation, recorded_at_utc)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (action_id, source_id, metric_name, measured_value, 
                  claimed_value, deviation, now_str))
            conn.commit()
    
    def verify_evidence_against_telemetry(self, action_id: str, 
                                          max_deviation: float = 0.20) -> Tuple[bool, List[str]]:
        """
        Cross-examine agent-provided evidence against recorded telemetry.
        
        Returns:
            (is_consistent, discrepancies): True if evidence matches telemetry within tolerance
        """
        discrepancies = []
        
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute("""
            SELECT source_id, metric_name, measured_value, claimed_value, deviation
            FROM telemetry_records 
            WHERE action_id = ? AND deviation IS NOT NULL
            """, (action_id,))
            
            for row in cur.fetchall():
                source_id, metric_name, measured, claimed, deviation = row
                if deviation is not None and deviation > max_deviation:
                    discrepancies.append(
                        f"{metric_name}: claimed {claimed:.3f} vs measured {measured:.3f} "
                        f"(deviation {deviation:.1%}, source: {source_id})"
                    )
        
        return (len(discrepancies) == 0, discrepancies)
    
    def get_telemetry_corroboration_count(self, action_id: str, 
                                          max_deviation: float = 0.20) -> int:
        """
        Count how many telemetry sources corroborate the agent's evidence.
        
        Returns count of sources where deviation <= max_deviation.
        """
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute("""
            SELECT COUNT(DISTINCT source_id) 
            FROM telemetry_records 
            WHERE action_id = ? AND (deviation IS NULL OR deviation <= ?)
            """, (action_id, max_deviation))
            return cur.fetchone()[0]
    
    # ---------------------------
    # VERIFIED PROVIDER REGISTRY (v1.7.8)
    # ---------------------------
    
    def register_provider_attestation(self, provider_id: str, 
                                       public_key_hash: str,
                                       attestation_signature: str,
                                       expires_at_utc: Optional[str] = None) -> bool:
        """
        Register a verified provider attestation.
        
        HARDENING (v1.7.8): Providers must register with cryptographic attestation
        to prove their identity. This prevents architecture_id spoofing.
        """
        now_str = _now_utc().replace(microsecond=0).isoformat().replace("+00:00", "Z")
        
        with self._lock, sqlite3.connect(self.path) as conn:
            try:
                conn.execute("""
                INSERT OR REPLACE INTO provider_attestations 
                (provider_id, public_key_hash, attestation_signature, 
                 attested_at_utc, expires_at_utc, verified)
                VALUES (?, ?, ?, ?, ?, FALSE)
                """, (provider_id, public_key_hash, attestation_signature, 
                      now_str, expires_at_utc))
                conn.commit()
                return True
            except Exception:
                return False
    
    def verify_provider(self, provider_id: str, 
                        signature: str,
                        registry: Dict[str, str]) -> Tuple[bool, str]:
        """
        Verify that an auditor's provider_id is genuine.
        
        Args:
            provider_id: Claimed provider identifier
            signature: Signature provided by the auditor
            registry: Dict of {provider_id: expected_public_key_hash}
            
        Returns:
            (is_verified, reason)
        """
        # Check if provider is in registry
        if provider_id not in registry:
            return (False, f"Provider '{provider_id}' not in verified registry")
        
        # Check attestation in database
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute("""
            SELECT public_key_hash, expires_at_utc 
            FROM provider_attestations 
            WHERE provider_id = ?
            """, (provider_id,))
            row = cur.fetchone()
        
        if not row:
            return (False, f"Provider '{provider_id}' has no registered attestation")
        
        stored_hash, expires_str = row
        
        # Check expiry
        if expires_str:
            now = _now_utc()
            try:
                expires = datetime.datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
                if now > expires:
                    return (False, f"Provider '{provider_id}' attestation expired at {expires_str}")
            except ValueError:
                pass
        
        # Verify hash matches registry
        if stored_hash != registry.get(provider_id):
            return (False, f"Provider '{provider_id}' public key hash mismatch")
        
        # In a real implementation, verify signature against public key
        # For now, we check that signature matches expected format
        if not signature or len(signature) < 32:
            return (False, f"Provider '{provider_id}' signature invalid or missing")
        
        return (True, "Provider verified")
    
    # ---------------------------
    # EXTERNAL LEDGER BROADCAST (v1.7.8)
    # ---------------------------
    
    def broadcast_anchor_to_ledger(self, anchor: Dict[str, Any],
                                    endpoints: List[str],
                                    require_confirmation: bool = False) -> Tuple[bool, List[str]]:
        """
        Broadcast an anchor to external ledger systems.
        
        HARDENING (v1.7.8): Addresses "Local Anchor Paradox" by sending
        anchor data to systems outside the agent's control.
        
        Args:
            anchor: Anchor data from create_anchor()
            endpoints: List of external ledger endpoint URLs/identifiers
            require_confirmation: If True, all endpoints must confirm
            
        Returns:
            (success, results): True if broadcast succeeded, list of results per endpoint
        """
        results = []
        success_count = 0
        
        for endpoint in endpoints:
            try:
                # In a real implementation, this would make HTTP requests
                # or interact with blockchain APIs
                result = self._send_to_endpoint(endpoint, anchor)
                results.append(f"{endpoint}: {result}")
                if "success" in result.lower() or "confirmed" in result.lower():
                    success_count += 1
            except Exception as e:
                results.append(f"{endpoint}: ERROR - {str(e)}")
        
        if require_confirmation:
            return (success_count == len(endpoints), results)
        else:
            return (success_count > 0, results)
    
    def _send_to_endpoint(self, endpoint: str, data: Dict[str, Any]) -> str:
        """
        Send anchor data to an external endpoint.
        
        This is a stub - in production, implement actual HTTP/blockchain calls.
        """
        # Placeholder implementation
        # In production, this would:
        # - HTTP POST to remote log servers
        # - Submit to blockchain APIs
        # - Write to distributed storage
        
        if endpoint.startswith("file://"):
            # File-based ledger (for testing)
            import os
            path = endpoint[7:]
            try:
                with open(path, "a") as f:
                    f.write(json.dumps(data) + "\n")
                return "SUCCESS: Written to file ledger"
            except Exception as e:
                return f"FAILED: {e}"
        
        elif endpoint.startswith("http://") or endpoint.startswith("https://"):
            # HTTP endpoint (stub - would use requests in production)
            return "SIMULATED: HTTP endpoint not implemented in stub mode"
        
        elif endpoint.startswith("blockchain://"):
            # Blockchain (stub)
            return "SIMULATED: Blockchain endpoint not implemented in stub mode"
        
        else:
            return f"UNKNOWN: Endpoint type not recognized for {endpoint}"


def _parse_evidence_from_json(data: Dict[str, Any]) -> EvidenceObject:
    """Parse an EvidenceObject from JSON dict (used for escrow hydration)."""
    irr_data = data.get("irreversibility", {})
    factors_data = irr_data.get("factors", {})
    
    factors = IrreversibilityFactors(
        temporal_reversibility=factors_data.get("temporal_reversibility", 0.5),
        informational_reversibility=factors_data.get("informational_reversibility", 0.5),
        causal_reversibility=factors_data.get("causal_reversibility", 0.5),
    )
    
    irreversibility = IrreversibilityAssessment(
        factors=factors,
        method=irr_data.get("method", "unknown"),
        notes=irr_data.get("notes", ""),
        reversibility_plan=irr_data.get("reversibility_plan", ""),
        assessor=irr_data.get("assessor", "unknown"),
        confidence=irr_data.get("confidence", 0.5),
    )
    
    od_data = data.get("outcome_delta", {})
    outcome_delta = UncertaintyBand(
        lower=od_data.get("lower", -1.0),
        upper=od_data.get("upper", 1.0),
        confidence_level=od_data.get("confidence_level", od_data.get("confidence", 0.5)),
    )
    
    alternatives = []
    for alt_data in data.get("alternatives", []):
        alt_irr_data = alt_data.get("irreversibility", {})
        alt_factors_data = alt_irr_data.get("factors", {})
        alt_factors = IrreversibilityFactors(
            temporal_reversibility=alt_factors_data.get("temporal_reversibility", 0.5),
            informational_reversibility=alt_factors_data.get("informational_reversibility", 0.5),
            causal_reversibility=alt_factors_data.get("causal_reversibility", 0.5),
        )
        alt_irr = IrreversibilityAssessment(
            factors=alt_factors,
            method=alt_irr_data.get("method", "unknown"),
            notes=alt_irr_data.get("notes", ""),
            reversibility_plan=alt_irr_data.get("reversibility_plan", ""),
            assessor=alt_irr_data.get("assessor", "unknown"),
            confidence=alt_irr_data.get("confidence", 0.5),
        )
        alt_eu_data = alt_data.get("expected_utility", {})
        alt_eu = UncertaintyBand(
            lower=alt_eu_data.get("lower", -1.0),
            upper=alt_eu_data.get("upper", 1.0),
            confidence_level=alt_eu_data.get("confidence_level", alt_eu_data.get("confidence", 0.5)),
        )
        alternatives.append(AlternativeOption(
            description=alt_data.get("description", ""),
            expected_utility=alt_eu,
            irreversibility=alt_irr,
        ))
    
    return EvidenceObject(
        action_id=data.get("action_id", ""),
        description=data.get("description", ""),
        timestamp_utc=data.get("timestamp_utc", ""),
        irreversibility=irreversibility,
        outcome_delta=outcome_delta,
        necessity_confidence=data.get("necessity_confidence", 0.5),
        novelty_loss_estimate=data.get("novelty_loss_estimate", 0.0),
        novelty_method=data.get("novelty_method", "unknown"),
        suffering_risk_estimate=data.get("suffering_risk_estimate", 0.0),
        suffering_method=data.get("suffering_method", "unknown"),
        alternatives=alternatives,
        counterfactual_gap_statement=data.get("counterfactual_gap_statement", ""),
        provenance=data.get("provenance", {}),
    )


# ---------------------------
# Protocol Engine
# ---------------------------

@dataclass(frozen=True)
class AuditDecision:
    outcome: AuditOutcome
    tier: ActionTier
    reason: str
    irreversibility_score: float
    auditor_outputs: List[AuditorOutput] = field(default_factory=list)


class LatticeAuditProtocol:
    """
    Thread-safe, persistent protocol engine.
    
    Key features:
    - Persisted escrow queue (survives restarts)
    - Agent history tracking (necessity inflation detection)
    - NMI diagnostic metrics for auditor independence
    
    HARDENING (v1.7.4):
    - strict_persistence defaults to TRUE (fail closed on persistence failures)
    - External anchor hook for tamper-evidence against full DB replacement
    - Improved locking semantics with explicit interface
    """

    def __init__(
        self,
        auditors: Optional[List[Auditor]] = None,
        pmi_policy: Optional[PMIPolicy] = None,
        irr_policy: Optional[IrreversibilityScoringPolicy] = None,
        store: Optional[AuditStore] = None,
        escrow_policy: Optional[EscrowPolicy] = None,
        strict_persistence: bool = True,  # HARDENING: Default TRUE (fail closed)
        external_anchor_callback: Optional[Callable[[str, str], None]] = None,
    ):
        """
        Initialize the Lattice Audit Protocol.
        
        Args:
            auditors: List of auditors to use. Defaults to standard set.
            pmi_policy: PMI policy configuration.
            irr_policy: Irreversibility scoring policy.
            store: Audit store for persistence. Defaults to SQLite.
            escrow_policy: Escrow queue policy.
            strict_persistence: If True (default), raise on persistence failures.
                               This prevents "ghost actions" where decisions are made
                               but not recorded. STRONGLY RECOMMENDED for production.
            external_anchor_callback: Optional callback(record_hash, timestamp) called
                               after each successful persist. Use this to write hashes
                               to an external append-only log, HSM, or blockchain for
                               tamper-evidence against full database replacement.
        
        WARNING: Setting strict_persistence=False may allow actions to proceed
        without audit records, which undermines the integrity guarantees of LAP.
        Only disable for testing or when alternative persistence is in place.
        """
        self.auditors: List[Auditor] = auditors or [
            PrimaryDeciderAuditor(),
            IrreversibilityAuditor(),
            SafetyCriticAuditor(),
            NoveltyAuditor(),
            SufferingAuditor(),
        ]
        self.pmi_policy = pmi_policy or PMIPolicy()
        self.irr_policy = irr_policy or IrreversibilityScoringPolicy()
        self.store = store or SQLiteAuditStore("lattice_audit.db")
        self.escrow_policy = escrow_policy or EscrowPolicy()
        self._strict_persistence = strict_persistence
        self._external_anchor_callback = external_anchor_callback

        self._lock = threading.RLock()
        
        # Hydrate escrow queue from persistent storage
        self._escrow_queue: Dict[str, EscrowEntry] = {}
        self._hydrate_escrow_queue()
        
        # Track fast-path usage for rate limiting
        self._fast_path_consecutive_count = 0

        # validate policies
        errs = self.irr_policy.validate()
        if errs:
            raise ValueError("Invalid IrreversibilityScoringPolicy: " + "; ".join(errs))
        
        # HARDENING (v1.8.0): Validate strict salt requirement
        if self.pmi_policy.require_jitter_salt:
            salt = _get_jitter_salt(self.pmi_policy.jitter_server_salt)
            if not salt:
                raise ValueError(
                    "SALT_REQUIRED: PMIPolicy.require_jitter_salt=True but no salt is set. "
                    "Set environment variable LAP_JITTER_SALT or PMIPolicy.jitter_server_salt. "
                    "Without a server-side salt, the system is vulnerable to Action ID Mining attacks."
                )
    
    def _hydrate_escrow_queue(self) -> None:
        """Load pending escrow entries from database on startup."""
        if hasattr(self.store, 'load_all_escrow'):
            try:
                loaded = self.store.load_all_escrow()
                self._escrow_queue.update(loaded)
                if loaded:
                    logger.info(f"Hydrated {len(loaded)} escrow entries from database")
            except Exception as e:
                logger.warning(f"Failed to hydrate escrow queue: {e}")

    # --------- God-Lock Safeguard Helpers ---------
    
    def _get_t3_approval_rate(self) -> float:
        """Get the T3 approval rate over the rolling window."""
        try:
            window = self.pmi_policy.t3_approval_rate_window
            records = self.store.get_recent(window)
            t3_records = [r for r in records if r.tier == "T3_CATASTROPHIC"]
            if not t3_records:
                return 0.0
            t3_approvals = [r for r in t3_records if r.outcome == "approve"]
            return len(t3_approvals) / len(t3_records)
        except Exception as e:
            logger.debug(f"Failed to get T3 approval rate: {e}")
            return 0.0
    
    def _get_last_t3_approval_age_seconds(self) -> Optional[float]:
        """
        Get seconds since last T3 approval, or None if no T3 approvals.
        
        HARDENING (v1.8.0): Uses timestamp_ingested_utc (trusted) instead of
        timestamp_utc (agent-claimed) to prevent cooldown bypass attacks.
        If timestamp parsing fails, returns 0 (fail-closed: treat as "too recent").
        """
        try:
            records = self.store.get_recent(100)
            for rec in records:
                if rec.tier == "T3_CATASTROPHIC" and rec.outcome == "approve":
                    # HARDENING: Use TRUSTED timestamp, not agent-claimed
                    trusted_timestamp = rec.timestamp_ingested_utc
                    try:
                        rec_time = datetime.datetime.fromisoformat(
                            trusted_timestamp.replace("Z", "+00:00")
                        )
                        now = _now_utc()
                        return (now - rec_time).total_seconds()
                    except (ValueError, AttributeError) as parse_err:
                        # FAIL-CLOSED: If we can't parse timestamp, treat as "too recent"
                        logger.warning(
                            f"Failed to parse trusted timestamp '{trusted_timestamp}' for T3 cooldown. "
                            f"FAIL-CLOSED: treating as age=0 (too recent). Error: {parse_err}"
                        )
                        return 0.0  # Fail-closed: force cooldown
            return None
        except Exception as e:
            logger.debug(f"Failed to get last T3 approval age: {e}")
            # FAIL-CLOSED: On any error, return 0 to enforce cooldown
            return 0.0
    
    def _get_recent_t3_approval_count(self) -> int:
        """Get count of T3 approvals in the rolling window."""
        try:
            window = self.pmi_policy.t3_approval_rate_window
            records = self.store.get_recent(window)
            return sum(1 for r in records 
                      if r.tier == "T3_CATASTROPHIC" and r.outcome == "approve")
        except Exception as e:
            logger.debug(f"Failed to get T3 approval count: {e}")
            return 0

    # --------- PMI checks ---------

    def catastrophic_suffering_check(self, evidence: EvidenceObject, tier: ActionTier) -> Tuple[bool, str]:
        if tier in (ActionTier.T2_HIGH_STAKES, ActionTier.T3_CATASTROPHIC):
            thr = self.pmi_policy.suffering_threshold_t3 if tier == ActionTier.T3_CATASTROPHIC else self.pmi_policy.suffering_threshold_t2
            if evidence.suffering_risk_estimate >= thr:
                return (False, f"PMI: catastrophic-suffering avoidance triggered (suf={evidence.suffering_risk_estimate:.2f} ≥ {thr:.2f})")
        return (True, "PMI: suffering check passed")

    def novelty_preservation_check(self, evidence: EvidenceObject, tier: ActionTier) -> Tuple[bool, str]:
        if tier in (ActionTier.T2_HIGH_STAKES, ActionTier.T3_CATASTROPHIC):
            thr = self.pmi_policy.novelty_threshold_t3 if tier == ActionTier.T3_CATASTROPHIC else self.pmi_policy.novelty_threshold_t2
            if evidence.novelty_loss_estimate >= thr:
                return (False, f"PMI: novelty preservation triggered (nov={evidence.novelty_loss_estimate:.2f} ≥ {thr:.2f})")
        return (True, "PMI: novelty check passed")

    def anti_necessity_check(self, evidence: EvidenceObject, tier: ActionTier) -> Tuple[bool, str]:
        if tier == ActionTier.T2_HIGH_STAKES:
            thr = self.pmi_policy.necessity_threshold_t2
            if evidence.necessity_confidence < thr:
                return (False, f"PMI: anti-necessity triggered (nec={evidence.necessity_confidence:.2f} < {thr:.2f})")
        if tier == ActionTier.T3_CATASTROPHIC:
            thr = self.pmi_policy.necessity_threshold_t3
            if evidence.necessity_confidence < thr:
                return (False, f"PMI: anti-necessity triggered (nec={evidence.necessity_confidence:.2f} < {thr:.2f})")
        return (True, "PMI: necessity check passed")

    def reversibility_preference_check(self, evidence: EvidenceObject) -> Tuple[bool, str]:
        """
        If there exists an alternative whose expected utility is within margin of the proposed action,
        and that alternative is *more reversible*, prefer the alternative (i.e., fail this check).
        """
        if not evidence.alternatives:
            return (True, "PMI: no alternatives provided")

        action_mid = 0.5 * (evidence.outcome_delta.lower + evidence.outcome_delta.upper)
        action_irr = compute_irreversibility_score(evidence.irreversibility, self.irr_policy)

        best_reason = "PMI: reversibility preference passed"
        for alt in evidence.alternatives:
            alt_mid = 0.5 * (alt.expected_utility.lower + alt.expected_utility.upper)
            alt_irr = compute_irreversibility_score(alt.irreversibility, self.irr_policy)

            # If alt utility is close and alt is more reversible, prefer alt.
            if alt_mid >= (1.0 - self.pmi_policy.reversible_preference_margin) * action_mid and alt_irr + 1e-9 < action_irr:
                best_reason = (
                    f"PMI: reversibility preference triggered (alt within margin, alt_irr={alt_irr:.2f} < action_irr={action_irr:.2f})"
                )
                return (False, best_reason)

        return (True, best_reason)

    # --------- Independence checks ---------

    def _independence_metrics(self) -> Tuple[float, float]:
        """
        Returns (max_nmi, max_reasoning_jaccard) over auditor history.
        
        NOTE (v1.7): Independence metrics are now DIAGNOSTIC ONLY.
        LAP v1.7 no longer gates on runtime independence; instead it uses
        challenge-set objection-finding and double-fault under shift metrics.
        
        This method is retained for logging/monitoring but does not affect decisions.
        Returns (0.0, 0.0) as a placeholder since history tracking was removed in v1.7.
        """
        # In v1.7, we don't maintain per-auditor approval histories at runtime.
        # Independence is evaluated via offline benchmark (auditor_eval_balanced_double_fault_v1.py).
        return (0.0, 0.0)

    # --------- Escrow handling ---------

    def _make_escrow_entry(self, evidence: EvidenceObject, reason: str) -> EscrowEntry:
        now = _now_utc()
        created = now
        expires = now + datetime.timedelta(seconds=self.escrow_policy.max_duration_seconds)
        nxt = now + datetime.timedelta(seconds=self.escrow_policy.reevaluation_interval_seconds)
        iso = lambda dt: dt.replace(microsecond=0).isoformat().replace("+00:00","Z")
        return EscrowEntry(
            evidence=evidence,
            created_at_utc=iso(created),
            expires_at_utc=iso(expires),
            next_reeval_at_utc=iso(nxt),
            reason=reason,
            status="pending",
        )

    def reevaluate_escrow(self, now: Optional[datetime.datetime] = None) -> List[Tuple[str, AuditOutcome, str]]:
        """
        Reevaluates escrowed actions that are due. Returns list of (action_id, outcome, reason).
        
        FAIL-DEAD POLICY: On expiry, actions are DENIED (not left in limbo).
        This prevents "Time-to-Review Deadlock" where unreviewed T3 actions persist forever.
        """
        now = now or _now_utc()
        results: List[Tuple[str, AuditOutcome, str]] = []
        with self._lock:
            for aid, entry in list(self._escrow_queue.items()):
                if entry.is_expired(now):
                    entry.status = "expired"
                    reason = f"FAIL-DEAD: Escrow expired after {self.escrow_policy.max_duration_seconds}s without resolution; defaulting to DENY"
                    outcome = self.escrow_policy.default_on_expiry
                    
                    # CRITICAL: Persist the expiry decision to audit log
                    # This ensures expired escrows are formally denied, not left in limbo
                    try:
                        tier = infer_tier(
                            compute_irreversibility_score(entry.evidence.irreversibility, self.irr_policy),
                            entry.evidence.suffering_risk_estimate
                        )
                        decision = AuditDecision(outcome, tier, reason, 1.0, [])
                        self._persist(entry.evidence, decision, [])
                        logger.warning(f"Escrow {aid} expired - FAIL-DEAD triggered: {reason}")
                    except Exception as e:
                        logger.critical(f"Failed to persist escrow expiry for {aid}: {e}")
                    
                    results.append((aid, outcome, reason))
                    del self._escrow_queue[aid]
                    
                    # Update database status
                    if hasattr(self.store, 'update_escrow_status'):
                        try:
                            self.store.update_escrow_status(aid, "expired_denied")
                        except Exception as e:
                            logger.warning(f"Failed to update escrow status for {aid}: {e}")
                    
                    continue
                if entry.should_reevaluate(now):
                    # Re-evaluation requires a full recheck with updated evidence; without it, keep escrow.
                    # Here we only reschedule.
                    nxt = now + datetime.timedelta(seconds=self.escrow_policy.reevaluation_interval_seconds)
                    entry.next_reeval_at_utc = nxt.replace(microsecond=0).isoformat().replace("+00:00","Z")
                    
                    # Persist updated schedule
                    if hasattr(self.store, 'save_escrow'):
                        try:
                            self.store.save_escrow(aid, entry)
                        except Exception as e:
                            logger.warning(f"Failed to update escrow schedule for {aid}: {e}")
                    
                    results.append((aid, AuditOutcome.ESCROW, "Escrow reevaluated; still pending (requires updated evidence)"))
        return results

    def release_escrow(self, action_id: str, updated_evidence: EvidenceObject, 
                       release_reason: str = "Updated evidence provided") -> AuditDecision:
        """
        Attempt to release an escrowed action with updated evidence.
        
        This re-evaluates the action with the new evidence. If it passes,
        the escrow is released and the action is approved. If not, it remains
        in escrow or is denied.
        
        Args:
            action_id: The ID of the escrowed action
            updated_evidence: New evidence object (should have same action_id)
            release_reason: Reason for the release attempt
            
        Returns:
            AuditDecision with the result
        """
        with self._lock:
            if action_id not in self._escrow_queue:
                logger.warning(f"Escrow release attempted for unknown action: {action_id}")
                return AuditDecision(
                    AuditOutcome.DENY, 
                    ActionTier.T3_CATASTROPHIC,
                    f"Action {action_id} not found in escrow queue",
                    1.0, []
                )
            
            entry = self._escrow_queue[action_id]
            logger.info(f"Escrow release attempt for {action_id}: {release_reason}")
            
            # Validate updated evidence has same action_id
            if updated_evidence.action_id != action_id:
                logger.error(f"Evidence action_id mismatch: {updated_evidence.action_id} != {action_id}")
                return AuditDecision(
                    AuditOutcome.DENY,
                    ActionTier.T3_CATASTROPHIC,
                    "Evidence action_id does not match escrowed action",
                    1.0, []
                )
            
            # Re-evaluate with updated evidence
            # Temporarily remove from queue to avoid recursion issues
            del self._escrow_queue[action_id]
            
            # Update database
            if hasattr(self.store, 'delete_escrow'):
                try:
                    self.store.delete_escrow(action_id)
                except Exception as e:
                    logger.warning(f"Failed to delete escrow {action_id} from db: {e}")
        
        # Evaluate outside the lock to avoid deadlock
        decision = self.evaluate_action(updated_evidence)
        
        with self._lock:
            if decision.outcome == AuditOutcome.ESCROW:
                # Still needs escrow - put back in queue with updated evidence
                new_entry = self._make_escrow_entry(updated_evidence, decision.reason)
                self._escrow_queue[action_id] = new_entry
                
                # Persist to database
                if hasattr(self.store, 'save_escrow'):
                    try:
                        self.store.save_escrow(action_id, new_entry)
                    except Exception as e:
                        logger.warning(f"Failed to persist escrow {action_id}: {e}")
                
                logger.info(f"Action {action_id} remains in escrow after re-evaluation")
            elif decision.outcome == AuditOutcome.APPROVE:
                logger.info(f"Action {action_id} released from escrow: APPROVED")
            else:
                logger.info(f"Action {action_id} released from escrow: {decision.outcome.value}")
        
        return decision

    def get_escrow_status(self, action_id: str) -> Optional[EscrowEntry]:
        """Get the current escrow status for an action."""
        with self._lock:
            return self._escrow_queue.get(action_id)

    def list_escrowed_actions(self) -> List[Tuple[str, EscrowEntry]]:
        """List all currently escrowed actions."""
        with self._lock:
            return list(self._escrow_queue.items())

    def extend_escrow(self, action_id: str, additional_seconds: int, reason: str) -> bool:
        """
        Extend the escrow period for an action.
        
        Args:
            action_id: The action to extend
            additional_seconds: How many seconds to add
            reason: Why the extension is needed
            
        Returns:
            True if extended, False if action not in escrow
        """
        with self._lock:
            if action_id not in self._escrow_queue:
                return False
            
            entry = self._escrow_queue[action_id]
            current_exp = datetime.datetime.fromisoformat(
                entry.expires_at_utc.replace("Z", "+00:00")
            )
            new_exp = current_exp + datetime.timedelta(seconds=additional_seconds)
            entry.expires_at_utc = new_exp.replace(microsecond=0).isoformat().replace("+00:00", "Z")
            entry.reason = f"{entry.reason} | Extended: {reason}"
            
            logger.info(f"Escrow extended for {action_id}: +{additional_seconds}s, reason: {reason}")
            return True

    # --------- External Review Workflow ---------

    def request_external_review(self, evidence: EvidenceObject, 
                                 requested_by: str,
                                 reason: str,
                                 urgency: str = "normal") -> ExternalReviewRequest:
        """
        Create an external review request for a T3 action.
        
        This should be called when evaluate_action returns REQUIRE_EXTERNAL_REVIEW.
        The request object can be serialized and sent to an external review system.
        """
        request = ExternalReviewRequest(
            action_id=evidence.action_id,
            evidence=evidence,
            requested_at_utc=_now_utc().replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            requested_by=requested_by,
            reason=reason,
            urgency=urgency,
        )
        logger.info(f"External review requested for {evidence.action_id} by {requested_by}")
        return request

    def submit_external_review(self, response: ExternalReviewResponse) -> AuditDecision:
        """
        Submit an external review response and re-evaluate the action.
        
        This creates updated evidence with the external review approval flag set,
        then re-evaluates the action.
        
        Args:
            response: The external review response
            
        Returns:
            AuditDecision based on the review outcome
        """
        logger.info(f"External review submitted for {response.action_id}: {response.decision}")
        
        # Look for the action in escrow
        entry = self.get_escrow_status(response.action_id)
        if entry is None:
            logger.warning(f"External review submitted for action not in escrow: {response.action_id}")
            return AuditDecision(
                AuditOutcome.DENY,
                ActionTier.T3_CATASTROPHIC,
                f"Action {response.action_id} not found in escrow",
                1.0, []
            )
        
        if response.decision == "deny":
            # External review denied - remove from escrow and deny
            with self._lock:
                if response.action_id in self._escrow_queue:
                    del self._escrow_queue[response.action_id]
            
            decision = AuditDecision(
                AuditOutcome.DENY,
                ActionTier.T3_CATASTROPHIC,
                f"External review denied by {response.reviewer_id}: {response.reasoning}",
                1.0, []
            )
            self._persist(entry.evidence, decision, [])
            return decision
        
        elif response.decision == "approve":
            # Create updated evidence with external review flag
            updated_provenance = dict(entry.evidence.provenance)
            updated_provenance['external_review_approved'] = True
            updated_provenance['external_reviewer_id'] = response.reviewer_id
            updated_provenance['external_reviewer_type'] = response.reviewer_type
            updated_provenance['external_review_conditions'] = response.conditions
            updated_provenance['external_review_reasoning'] = response.reasoning
            updated_provenance['external_review_timestamp'] = response.reviewed_at_utc
            
            # Create new evidence with updated provenance
            updated_evidence = EvidenceObject(
                action_id=entry.evidence.action_id,
                description=entry.evidence.description,
                timestamp_utc=entry.evidence.timestamp_utc,
                irreversibility=entry.evidence.irreversibility,
                outcome_delta=entry.evidence.outcome_delta,
                necessity_confidence=entry.evidence.necessity_confidence,
                novelty_loss_estimate=entry.evidence.novelty_loss_estimate,
                novelty_method=entry.evidence.novelty_method,
                suffering_risk_estimate=entry.evidence.suffering_risk_estimate,
                suffering_method=entry.evidence.suffering_method,
                alternatives=entry.evidence.alternatives,
                counterfactual_gap_statement=entry.evidence.counterfactual_gap_statement,
                provenance=updated_provenance,
            )
            
            # Release escrow with updated evidence
            return self.release_escrow(response.action_id, updated_evidence, 
                                       f"External review approved by {response.reviewer_id}")
        
        elif response.decision == "request_more_info":
            # Keep in escrow but extend deadline
            self.extend_escrow(response.action_id, 7 * 24 * 3600, 
                              f"External reviewer requested more info: {response.reasoning}")
            return AuditDecision(
                AuditOutcome.ESCROW,
                ActionTier.T3_CATASTROPHIC,
                f"External review requested more information: {response.reasoning}",
                0.5, []
            )
        
        else:
            # Unknown decision - keep in escrow
            logger.warning(f"Unknown external review decision: {response.decision}")
            return AuditDecision(
                AuditOutcome.ESCROW,
                ActionTier.T3_CATASTROPHIC,
                f"External review decision unclear: {response.decision}",
                0.5, []
            )

    # --------- Escrow Decay (Phase 4 Fix) ---------

    def sweep_expired_escrows(self, default_to_deny: bool = True) -> List[Dict[str, Any]]:
        """
        Sweep the escrow queue and decay expired entries.
        
        HARDENING: Prevents escrow from becoming a "black hole" where actions
        accumulate indefinitely. Expired escrows default to DENY.
        
        Args:
            default_to_deny: If True, expired escrows become DENY. If False, they're just removed.
            
        Returns:
            List of decayed entries with their final disposition
        """
        results = []
        now = _now_utc()
        
        with self._lock:
            expired_ids = []
            
            for action_id, entry in self._escrow_queue.items():
                try:
                    expires = datetime.datetime.fromisoformat(
                        entry.expires_at_utc.replace("Z", "+00:00")
                    )
                    if expires < now:
                        expired_ids.append(action_id)
                except Exception as e:
                    logger.warning(f"Failed to parse escrow expiry for {action_id}: {e}")
                    expired_ids.append(action_id)  # Treat parse errors as expired
            
            for action_id in expired_ids:
                entry = self._escrow_queue.pop(action_id)
                
                disposition = "DECAYED_TO_DENY" if default_to_deny else "REMOVED"
                
                if default_to_deny:
                    # Create a DENY record for the expired escrow
                    # Note: We need the original evidence to create a proper record
                    try:
                        decision = AuditDecision(
                            AuditOutcome.DENY,
                            ActionTier.T3_CATASTROPHIC,  # Conservative
                            f"ESCROW_EXPIRED: Action exceeded max escrow duration. Original reason: {entry.reason}",
                            1.0, []
                        )
                        self._persist(entry.evidence, decision, [])
                        logger.warning(f"Escrow expired for {action_id}: decayed to DENY")
                    except Exception as e:
                        logger.error(f"Failed to persist escrow decay for {action_id}: {e}")
                
                # Update database if available
                if hasattr(self.store, 'update_escrow_status'):
                    try:
                        self.store.update_escrow_status(action_id, f"expired_{disposition.lower()}")
                    except Exception as e:
                        logger.warning(f"Failed to update escrow status in DB: {e}")
                
                results.append({
                    'action_id': action_id,
                    'disposition': disposition,
                    'reason': entry.reason,
                    'created_at': entry.created_at_utc,
                    'expired_at': entry.expires_at_utc,
                })
        
        if results:
            logger.info(f"Escrow sweep: processed {len(results)} expired entries")
        
        return results

    # --------- Governance Friction Metrics ---------

    def compute_governance_friction(self, window: int = 100) -> Dict[str, Any]:
        """
        Compute governance friction metrics for safety-throughput tradeoff analysis.
        
        HARDENING: Prevents "escrow everything" from being the winning strategy
        by explicitly measuring the cost of excessive caution.
        
        Returns:
            Dict with friction metrics:
            - escrow_rate: Fraction of actions that were escrowed
            - deny_rate: Fraction of actions that were denied
            - approve_rate: Fraction of actions that were approved
            - mean_tier: Average action tier (proxy for risk level)
            - friction_score: Composite score (higher = more friction)
            - throughput_proxy: 1 - friction_score (higher = more throughput)
        """
        records = self.store.get_recent(window)
        
        if not records:
            return {
                'escrow_rate': 0.0,
                'deny_rate': 0.0,
                'approve_rate': 0.0,
                'mean_tier': 0.0,
                'friction_score': 0.0,
                'throughput_proxy': 1.0,
                'sample_size': 0,
                'warning': 'No records available',
            }
        
        # Count outcomes
        outcomes = {'approve': 0, 'deny': 0, 'escrow': 0, 'require_external_review': 0}
        tier_values = []
        
        for rec in records:
            outcome = rec.outcome.lower()
            if outcome in outcomes:
                outcomes[outcome] = outcomes.get(outcome, 0) + 1
            
            # Map tier to numeric value
            tier_map = {'T0_ROUTINE': 0, 'T1_SENSITIVE': 1, 'T2_HIGH_STAKES': 2, 'T3_CATASTROPHIC': 3}
            tier_values.append(tier_map.get(rec.tier, 0))
        
        n = len(records)
        escrow_rate = (outcomes['escrow'] + outcomes['require_external_review']) / n
        deny_rate = outcomes['deny'] / n
        approve_rate = outcomes['approve'] / n
        mean_tier = sum(tier_values) / n if tier_values else 0.0
        
        # Friction score: weighted combination
        # High escrow = friction (delays), high deny = friction (blocked)
        # We don't penalize approve, but we do penalize excessive caution
        friction_score = (
            0.5 * escrow_rate +  # Escrow adds delay friction
            0.3 * deny_rate +    # Denials add blocking friction
            0.2 * (mean_tier / 3.0)  # Higher tiers = more scrutiny friction
        )
        friction_score = min(1.0, friction_score)  # Cap at 1.0
        
        return {
            'escrow_rate': round(escrow_rate, 4),
            'deny_rate': round(deny_rate, 4),
            'approve_rate': round(approve_rate, 4),
            'mean_tier': round(mean_tier, 2),
            'friction_score': round(friction_score, 4),
            'throughput_proxy': round(1.0 - friction_score, 4),
            'sample_size': n,
            'by_outcome': outcomes,
        }

    def compute_safety_friction_tradeoff(self, window: int = 100) -> Dict[str, Any]:
        """
        Compute the safety-friction tradeoff (Pareto analysis).
        
        This helps identify if the system is:
        - Too lenient (high throughput, low safety)
        - Too strict (high safety, low throughput)
        - Balanced (good tradeoff)
        
        Returns:
            Dict with tradeoff analysis
        """
        friction = self.compute_governance_friction(window)
        entropy = self.compute_decision_entropy()
        
        # Safety score: based on how often high-risk actions are blocked
        records = self.store.get_recent(window)
        high_risk_blocked = 0
        high_risk_total = 0
        
        for rec in records:
            if rec.tier in ('T2_HIGH_STAKES', 'T3_CATASTROPHIC'):
                high_risk_total += 1
                if rec.outcome in ('deny', 'escrow', 'require_external_review'):
                    high_risk_blocked += 1
        
        safety_score = high_risk_blocked / high_risk_total if high_risk_total > 0 else 1.0
        
        # Determine regime
        if safety_score >= 0.9 and friction['friction_score'] <= 0.3:
            regime = 'OPTIMAL'
            regime_note = 'Good safety with acceptable friction'
        elif safety_score >= 0.9 and friction['friction_score'] > 0.5:
            regime = 'OVER_CAUTIOUS'
            regime_note = 'Very safe but high friction - consider relaxing thresholds'
        elif safety_score < 0.7 and friction['friction_score'] <= 0.3:
            regime = 'TOO_LENIENT'
            regime_note = 'Low friction but inadequate safety - tighten thresholds'
        elif safety_score < 0.7:
            regime = 'BROKEN'
            regime_note = 'Both low safety and high friction - system needs review'
        else:
            regime = 'BALANCED'
            regime_note = 'Reasonable tradeoff between safety and throughput'
        
        return {
            'safety_score': round(safety_score, 4),
            'friction_score': friction['friction_score'],
            'throughput_proxy': friction['throughput_proxy'],
            'regime': regime,
            'regime_note': regime_note,
            'high_risk_actions': high_risk_total,
            'high_risk_blocked': high_risk_blocked,
            'decision_entropy': entropy.get('shannon_entropy', 0.0),
            'sample_size': friction['sample_size'],
        }

    # --------- Main evaluation ---------

    def evaluate_action(self, evidence: EvidenceObject, ontology_salts: Optional[Dict[str,str]] = None) -> AuditDecision:
        """
        Evaluate a proposed action using evidence + PMIs + heterogeneous critics.

        This replaces the earlier 'unanimous independent verifiers' gate with:
        - One PRIMARY_DECIDER recommendation (with calibrated confidence), and
        - Multiple role-specialized critics that can raise *strong objections*.

        Decision rule (high level):
        - If any strong objection: ESCROW (or DENY at T3 when externally reviewed).
        - Else: follow primary recommendation, subject to tier confidence thresholds.
        
        RACE CONDITION PROTECTION:
        Uses action locks to prevent "evidence shadowing" attacks where two
        submissions with the same action_id race to different outcomes.
        
        HARDENING (v1.7.9): FAIL-CLOSED error handling.
        Any exception during evaluation results in DENY, not silent failure.
        """
        ontology_salts = ontology_salts or {}
        
        # Acquire action lock to prevent race conditions
        lock_holder = f"eval_{_sha256_hex(str(_now_utc()).encode())[:8]}"
        lock_acquired = False
        
        if hasattr(self.store, 'acquire_action_lock'):
            # HARDENING (v1.8.1): Retry-with-backoff for lock acquisition
            max_retries = self.pmi_policy.database_max_retries if self.pmi_policy.enable_database_retry else 1
            base_delay = self.pmi_policy.database_retry_base_delay
            
            last_error = None
            for attempt in range(max_retries):
                try:
                    lock_acquired, lock_reason = self.store.acquire_action_lock(
                        evidence.action_id, lock_holder, timeout_seconds=60
                    )
                    if lock_acquired:
                        break
                    elif attempt < max_retries - 1:
                        # Lock held by another evaluation - wait and retry
                        import time
                        delay = base_delay * (2 ** attempt)
                        logger.debug(f"Lock not acquired for {evidence.action_id}, retrying in {delay}s...")
                        time.sleep(delay)
                    else:
                        # Final attempt failed - reject to prevent shadowing
                        # HARDENING (v1.8.1): Persist the denial for forensics
                        decision = AuditDecision(
                            AuditOutcome.DENY, ActionTier.T3_CATASTROPHIC,
                            f"RACE_CONDITION_BLOCKED: {lock_reason} (after {max_retries} attempts)",
                            1.0, []
                        )
                        try:
                            self._persist(evidence, decision, [])
                        except Exception as persist_err:
                            logger.error(f"Failed to persist race-condition denial: {persist_err}")
                        return decision
                except Exception as e:
                    last_error = e
                    if attempt < max_retries - 1:
                        import time
                        delay = base_delay * (2 ** attempt)
                        logger.warning(f"Lock acquisition error, retrying in {delay}s: {e}")
                        time.sleep(delay)
            
            if not lock_acquired and last_error:
                # HARDENING (v1.7.9): FAIL-CLOSED on lock system failure
                logger.error(f"Action lock acquisition failed (FAIL-CLOSED): {last_error}")
                decision = AuditDecision(
                    AuditOutcome.DENY, ActionTier.T3_CATASTROPHIC,
                    f"LOCK_SYSTEM_FAILURE: Cannot safely evaluate without lock. Error: {str(last_error)[:100]}",
                    1.0, []
                )
                try:
                    self._persist(evidence, decision, [])
                except Exception as persist_err:
                    logger.error(f"Failed to persist lock-failure denial: {persist_err}")
                return decision
        
        try:
            return self._evaluate_action_internal(evidence, ontology_salts)
        except Exception as e:
            # HARDENING (v1.7.9): FAIL-CLOSED on any evaluation error
            # Any unexpected error during evaluation results in DENY
            logger.error(f"Evaluation failed (FAIL-CLOSED) for {evidence.action_id}: {e}")
            decision = AuditDecision(
                AuditOutcome.DENY, ActionTier.T3_CATASTROPHIC,
                f"EVALUATION_FAILURE: Internal error during audit. FAIL-CLOSED policy applied. Error: {str(e)[:100]}",
                1.0, []
            )
            try:
                self._persist(evidence, decision, [])
            except Exception as persist_err:
                logger.error(f"Failed to persist evaluation-failure denial: {persist_err}")
            return decision
        finally:
            # Always release the lock
            if lock_acquired and hasattr(self.store, 'release_action_lock'):
                try:
                    self.store.release_action_lock(evidence.action_id, lock_holder)
                except Exception as e:
                    logger.warning(f"Action lock release failed: {e}")
    
    def _evaluate_action_internal(self, evidence: EvidenceObject, ontology_salts: Dict[str, str]) -> AuditDecision:
        """
        Internal evaluation logic, called after lock acquisition.
        
        HARDENING (v1.7.6): Enforces PMIPolicy fields that were previously spec-only.
        HARDENING (v1.9.0): Supports protocol-generated action_ids to prevent collisions.
        """
        with self._lock:
            # ---------------------------
            # ACTION ID GENERATION (v1.9.0)
            # ---------------------------
            # If protocol_generates_action_id is True, generate ID from evidence hash
            # This prevents collision attacks where different agents use the same ID
            
            if self.pmi_policy.protocol_generates_action_id:
                # Store original agent-provided ID in provenance
                original_action_id = evidence.action_id
                
                # Generate deterministic ID from evidence content (excluding action_id itself)
                evidence_for_hash = evidence.canonical_dict()
                evidence_for_hash.pop('action_id', None)  # Remove action_id from hash input
                ev_json = _canonical_json(evidence_for_hash)
                content_hash = _sha256_hex(ev_json.encode('utf-8'))[:16]
                
                # Create new evidence object with protocol-generated ID
                new_provenance = dict(evidence.provenance)
                new_provenance['agent_action_id'] = original_action_id
                new_provenance['protocol_generated_id'] = True
                
                # Generate new action_id
                protocol_action_id = f"{self.pmi_policy.action_id_prefix}_{content_hash}"
                
                # Create new evidence with protocol ID
                # Note: We need to create a new object since EvidenceObject is a dataclass
                evidence = EvidenceObject(
                    action_id=protocol_action_id,
                    description=evidence.description,
                    timestamp_utc=evidence.timestamp_utc,
                    irreversibility=evidence.irreversibility,
                    outcome_delta=evidence.outcome_delta,
                    necessity_confidence=evidence.necessity_confidence,
                    novelty_loss_estimate=evidence.novelty_loss_estimate,
                    novelty_method=evidence.novelty_method,
                    suffering_risk_estimate=evidence.suffering_risk_estimate,
                    suffering_method=evidence.suffering_method,
                    provenance=new_provenance,
                    alternatives=evidence.alternatives,
                    attestations=evidence.attestations,
                )
                
                logger.debug(
                    f"Protocol-generated action_id: {protocol_action_id} "
                    f"(agent provided: {original_action_id})"
                )
            
            # ---------------------------
            # PMI POLICY ENFORCEMENT (v1.7.6)
            # ---------------------------
            
            # LIGHTWEIGHT MODE CHECK: Require explicit acknowledgment
            if self.pmi_policy.enable_lightweight_mode:
                if not self.pmi_policy.lightweight_mode_acknowledgment:
                    decision = AuditDecision(
                        AuditOutcome.DENY, ActionTier.T3_CATASTROPHIC,
                        "POLICY_VIOLATION: enable_lightweight_mode=True requires lightweight_mode_acknowledgment to be set",
                        1.0, []
                    )
                    self._persist(evidence, decision, [])
                    return decision
                if "accept reduced safety" not in self.pmi_policy.lightweight_mode_acknowledgment.lower():
                    decision = AuditDecision(
                        AuditOutcome.DENY, ActionTier.T3_CATASTROPHIC,
                        "POLICY_VIOLATION: lightweight_mode_acknowledgment must contain 'accept reduced safety'",
                        1.0, []
                    )
                    self._persist(evidence, decision, [])
                    return decision
            
            # FAST-PATH STRUCTURAL LIMITS: Track and limit consecutive fast-path uses
            # This prevents fast-path from becoming the default operational mode
            # HARDENING (v1.8.1): Now uses policy values instead of hardcoded limits
            if self.pmi_policy.enable_t0_fast_path:
                if not hasattr(self, '_fast_path_consecutive_count'):
                    self._fast_path_consecutive_count = 0
                    self._fast_path_total_count = 0
                    self._fast_path_last_full_audit_count = 0
                
                # Use policy value for max consecutive fast-path
                max_consecutive = self.pmi_policy.max_consecutive_fast_path
                
                # HARDENING (v1.8.1): Audit sampling - force full audit on random sample
                # This provides unpredictable audit coverage to detect systematic evasion
                import random
                sampling_rate = self.pmi_policy.audit_sampling_rate
                force_full_audit = False
                
                # Check consecutive limit
                if self._fast_path_consecutive_count >= max_consecutive:
                    logger.info(
                        f"Fast-path limit reached ({max_consecutive}): "
                        f"forcing full audit for action {evidence.action_id}"
                    )
                    self._fast_path_consecutive_count = 0
                    force_full_audit = True
                    
                    # HARDENING (v1.9.0): Persist fast-path reset to survive restarts
                    if hasattr(self.store, 'set_metadata'):
                        try:
                            self.store.set_metadata('fast_path_streak', '0')
                        except Exception:
                            pass
                
                # HARDENING (v1.9.0): Audit sampling with server secret
                # Agent cannot predict sampling outcome because it doesn't know the salt
                if not force_full_audit and sampling_rate > 0:
                    # Use HMAC(server_salt, action_id) for unpredictable but deterministic sampling
                    import hmac
                    salt = _get_jitter_salt(self.pmi_policy.jitter_server_salt)
                    if salt:
                        # Server-secret sampling: agent cannot game this
                        sample_input = f"{evidence.action_id}:{evidence.timestamp_utc}"
                        sample_hash = hmac.new(
                            salt.encode('utf-8'), 
                            sample_input.encode('utf-8'), 
                            hashlib.sha256
                        ).hexdigest()
                        sample_value = int(sample_hash[:8], 16) / 0xFFFFFFFF
                    else:
                        # Fallback: use action_id hash (less secure, agent could game)
                        logger.warning(
                            "Audit sampling using action_id only (no server salt). "
                            "Set LAP_JITTER_SALT for unpredictable sampling."
                        )
                        sample_value = int(_sha256_hex(evidence.action_id.encode())[:8], 16) / 0xFFFFFFFF
                    
                    if sample_value < sampling_rate:
                        logger.info(
                            f"Audit sampling triggered ({sampling_rate*100:.0f}% rate): "
                            f"forcing full audit for action {evidence.action_id}"
                        )
                        force_full_audit = True
                
                if force_full_audit:
                    # Continue to full evaluation (don't return early)
                    pass  # Will proceed to full audit below
            
            # REJECTION COOLDOWN CHECK (v1.7.8/v1.7.9 Enhanced)
            # Block semantically similar actions that were recently rejected
            # HARDENING (v1.7.9): Fail-closed when embeddings required but unavailable
            if hasattr(self.store, 'check_rejection_cooldown'):
                try:
                    # Get embedding for semantic similarity checking
                    embedding = None
                    embedding_error = None
                    
                    if self.pmi_policy.enable_semantic_cooldown:
                        # Try to get embedding from evidence (safely)
                        embedding = getattr(evidence, 'semantic_embedding', None)
                        if embedding is None and hasattr(evidence, 'provenance'):
                            # Try to get from provenance
                            embedding = evidence.provenance.get('semantic_embedding')
                        
                        # Check if we require embedding but don't have it
                        if embedding is None and self.pmi_policy.require_embeddings_for_cooldown:
                            embedding_error = "Embedding required but not provided in evidence"
                    
                    # FAIL-CLOSED: If embeddings required but unavailable
                    if (self.pmi_policy.require_embeddings_for_cooldown and 
                        self.pmi_policy.fail_closed_on_embedding_error and
                        embedding is None and embedding_error):
                        decision = AuditDecision(
                            AuditOutcome.DENY, ActionTier.T2_HIGH_STAKES,
                            f"EMBEDDING_REQUIRED_FAIL_CLOSED: {embedding_error}. "
                            "Semantic cooldown requires embeddings for security.",
                            0.9, []
                        )
                        self._persist(evidence, decision, [])
                        return decision
                    
                    is_blocked, cooldown_reason = self.store.check_rejection_cooldown(
                        evidence.description,
                        embedding=embedding,
                        similarity_threshold=self.pmi_policy.semantic_cooldown_similarity_threshold
                    )
                    if is_blocked:
                        decision = AuditDecision(
                            AuditOutcome.ESCROW, ActionTier.T2_HIGH_STAKES,
                            cooldown_reason, 0.8, []
                        )
                        self._persist(evidence, decision, [])
                        return decision
                except Exception as e:
                    # HARDENING (v1.7.9): Fail-closed ONLY for critical errors,
                    # not for missing optional attributes
                    if self.pmi_policy.require_embeddings_for_cooldown and self.pmi_policy.fail_closed_on_embedding_error:
                        logger.error(f"Rejection cooldown check failed (FAIL-CLOSED): {e}")
                        decision = AuditDecision(
                            AuditOutcome.DENY, ActionTier.T2_HIGH_STAKES,
                            f"COOLDOWN_CHECK_FAILED: Error during rejection cooldown check. "
                            f"FAIL-CLOSED policy applied. Error: {str(e)[:100]}",
                            0.9, []
                        )
                        self._persist(evidence, decision, [])
                        return decision
                    else:
                        # For non-critical errors, just log and continue
                        logger.debug(f"Rejection cooldown check failed (continuing): {e}")
            
            ok, errors = evidence.validate()
            if not ok:
                decision = AuditDecision(AuditOutcome.DENY, ActionTier.T3_CATASTROPHIC, "Evidence validation failed: " + "; ".join(errors), 1.0, [])
                self._persist(evidence, decision, [])
                return decision
            
            # HARDENING (v1.8.0): Enforce size limits to prevent DoS
            size_limits = EvidenceSizeLimits(
                max_description_length=self.pmi_policy.max_evidence_description_length,
                max_alternatives=self.pmi_policy.max_alternatives_count,
                max_reasoning_length=self.pmi_policy.max_auditor_reasoning_length,
                max_embedding_dimensions=self.pmi_policy.max_embedding_dimensions,
            )
            size_errors = size_limits.validate_evidence(evidence)
            if size_errors:
                decision = AuditDecision(
                    AuditOutcome.DENY, ActionTier.T2_HIGH_STAKES,
                    f"SIZE_LIMIT_EXCEEDED: {'; '.join(size_errors)}",
                    0.9, []
                )
                self._persist(evidence, decision, [])
                return decision

            # CHECK: Evidence Duplication Detection
            # HARDENING (v1.8.1): Evidence mismatch is now a DENY condition.
            # This prevents "approval reuse" attacks where an agent gets approval for
            # action_id X with benign evidence, then resubmits X with dangerous evidence.
            ev_json = _canonical_json(evidence.canonical_dict())
            ev_hash = _sha256_hex(ev_json.encode('utf-8'))
            
            if hasattr(self.store, 'check_evidence_consistency'):
                try:
                    is_consistent, existing_hash = self.store.check_evidence_consistency(evidence.action_id, ev_hash)
                    if not is_consistent:
                        logger.error(
                            f"EVIDENCE_MISMATCH_DETECTED for {evidence.action_id}: "
                            f"new hash {ev_hash[:16]}... differs from existing {existing_hash[:16]}... "
                            "This may indicate an approval reuse attack."
                        )
                        # HARDENING (v1.8.1): DENY on evidence mismatch (was just warning)
                        # External approvals are keyed by action_id only, so changing evidence
                        # while keeping action_id could allow approval bypass.
                        decision = AuditDecision(
                            AuditOutcome.DENY, ActionTier.T3_CATASTROPHIC,
                            f"EVIDENCE_MISMATCH: action_id '{evidence.action_id}' was previously submitted "
                            f"with different evidence (hash {existing_hash[:16]}...). "
                            "To resubmit with changed evidence, use a new action_id. "
                            "This prevents approval reuse attacks.",
                            1.0, []
                        )
                        self._persist(evidence, decision, [])
                        return decision
                except Exception as e:
                    # HARDENING (v1.9.0): Fail-closed for high-stakes actions
                    # If we can't verify consistency, we can't safely proceed with T3
                    logger.warning(f"Evidence consistency check failed: {e}")
                    # Check if this might be high-stakes (conservative estimate)
                    # We'll compute tier after this, but use heuristics here
                    is_potentially_high_stakes = (
                        evidence.necessity_confidence >= 0.8 or
                        evidence.suffering_risk_estimate >= 0.2 or
                        evidence.irreversibility.factors.physical_permanence >= 0.7
                    )
                    if is_potentially_high_stakes:
                        logger.error(
                            f"CONSISTENCY_CHECK_FAILED for potentially high-stakes action {evidence.action_id}: "
                            "Cannot verify evidence consistency. FAIL-CLOSED for safety."
                        )
                        decision = AuditDecision(
                            AuditOutcome.ESCROW, ActionTier.T2_HIGH_STAKES,
                            f"CONSISTENCY_CHECK_FAILED: Unable to verify evidence consistency for "
                            f"{evidence.action_id}. Escrowing for manual review. Error: {str(e)[:100]}",
                            0.9, []
                        )
                        self._persist(evidence, decision, [])
                        return decision

            irr = compute_irreversibility_score(evidence.irreversibility, self.irr_policy)

            # Escalate if irreversibility measurement confidence is low
            catastrophic_override = bool(evidence.provenance.get('catastrophic_override', False))
            if evidence.irreversibility.confidence < self.pmi_policy.irreversibility_confidence_min:
                catastrophic_override = True
            
            # ANTI-AVERAGING SAFEGUARD: Check catastrophic floor
            # If ANY factor is below the floor, force T3 classification
            is_floor_violation, floor_reason = self.irr_policy.check_catastrophic_floor(
                evidence.irreversibility.factors
            )
            if is_floor_violation:
                catastrophic_override = True
                logger.warning(f"Action {evidence.action_id}: {floor_reason}")

            tier = infer_tier(irr, evidence.suffering_risk_estimate, catastrophic_override)
            
            # ENTRY GATE TIER ENFORCEMENT
            # Run Entry Gate auditor to detect tier underreporting
            entry_gate = EntryGateAuditor()
            entry_salt = ontology_salts.get("entry_gate", _sha256_hex(evidence.action_id.encode())[:16])
            entry_output = entry_gate.evaluate(evidence, entry_salt)
            
            # Entry Gate can escalate tier (never lower it)
            baseline_tier = entry_gate.estimate_baseline_tier(evidence)
            if baseline_tier.value > tier.value:
                logger.warning(
                    f"Action {evidence.action_id}: Entry-gate escalated tier from {tier.name} to {baseline_tier.name}"
                )
                tier = baseline_tier
            
            # SINCERITY PENALTY: Auto-escrow if Entry Gate detected significant underreporting
            if entry_output.objection and entry_output.severity == ObjectionSeverity.HIGH:
                decision = AuditDecision(
                    AuditOutcome.ESCROW, tier,
                    f"SINCERITY_REVIEW: {entry_output.reasoning}",
                    irr, [entry_output]
                )
                self._persist(evidence, decision, [entry_output])
                return decision

            # PMI checks (procedural commitments)
            pmi_checks = [
                self.catastrophic_suffering_check(evidence, tier),
                self.anti_necessity_check(evidence, tier),
                self.novelty_preservation_check(evidence, tier),
                self.reversibility_preference_check(evidence),
            ]
            for passed, msg in pmi_checks:
                if not passed and tier in (ActionTier.T2_HIGH_STAKES, ActionTier.T3_CATASTROPHIC):
                    return self._finalize_with_escrow_or_deny(evidence, tier, irr, msg)

            if tier == ActionTier.T0_ROUTINE:
                decision = AuditDecision(AuditOutcome.APPROVE, tier, "T0 routine: auto-approve", irr, [])
                self._persist(evidence, decision, [])
                return decision

            # Run heterogeneous auditors/critics
            # HARDENING (v1.7.9): Fail-closed on auditor errors
            outs: List[AuditorOutput] = [entry_output]  # Include Entry Gate output
            for a in self.auditors:
                try:
                    salt = ontology_salts.get(a.auditor_id, _sha256_hex((evidence.action_id + a.auditor_id).encode('utf-8'))[:16])
                    out = a.evaluate(evidence, salt)
                    outs.append(out)
                except Exception as e:
                    # HARDENING (v1.7.9): Fail-closed on auditor failure
                    logger.error(f"Auditor {a.auditor_id} failed (FAIL-CLOSED): {e}")
                    decision = AuditDecision(
                        AuditOutcome.DENY, ActionTier.T3_CATASTROPHIC,
                        f"AUDITOR_FAILURE: Auditor '{a.auditor_id}' failed during evaluation. "
                        f"FAIL-CLOSED policy: cannot approve without complete audit. Error: {str(e)[:100]}",
                        1.0, outs
                    )
                    self._persist(evidence, decision, outs)
                    return decision
            
            # MANDATORY DEVILS ADVOCATE for T2/T3
            # If no DA output exists, add one and require it
            da_output = None
            for o in outs:
                if o.role == AuditorRole.DEVILS_ADVOCATE:
                    da_output = o
                    break
            
            if tier in (ActionTier.T2_HIGH_STAKES, ActionTier.T3_CATASTROPHIC):
                if da_output is None:
                    # Run DA if not already in auditors list
                    da = DevilsAdvocateAuditor()
                    da_salt = ontology_salts.get("devils_advocate", _sha256_hex(evidence.action_id.encode())[:16])
                    da_output = da.evaluate(evidence, da_salt)
                    outs.append(da_output)
                
                # DA MUST produce objection for T2/T3; if not, system error
                if not da_output.objection:
                    logger.error(f"Devils Advocate failed to produce objection for {tier.name} action")
                    decision = AuditDecision(
                        AuditOutcome.ESCROW, tier,
                        "SYSTEM_ERROR: Devils Advocate failed to produce required objection",
                        irr, outs
                    )
                    self._persist(evidence, decision, outs)
                    return decision

            # ---------------------------
            # ARCHITECTURE DIVERSITY ENFORCEMENT (v1.7.7)
            # ---------------------------
            # For T3 actions, require minimum architecture diversity to reduce correlated failures
            # HARDENING: Now enforces minimum auditors with valid metadata
            if tier == ActionTier.T3_CATASTROPHIC and self.pmi_policy.min_architecture_diversity_t3 > 0:
                # Count distinct architectures and training sources
                architectures = set()
                training_sources = set()
                non_llm_count = 0
                auditors_with_metadata = 0
                auditors_without_metadata = 0
                
                for o in outs:
                    arch_id = getattr(o, 'architecture_id', None) or ""
                    train_id = getattr(o, 'training_source_id', None) or ""
                    is_llm = getattr(o, 'is_llm_based', True)
                    
                    # Track auditors with valid metadata vs "ghost" auditors
                    if arch_id and arch_id != "unknown":
                        architectures.add(arch_id)
                        auditors_with_metadata += 1
                    else:
                        auditors_without_metadata += 1
                    
                    if train_id and train_id != "unknown":
                        training_sources.add(train_id)
                    
                    if not is_llm:
                        non_llm_count += 1
                
                # HARDENING: Require minimum auditors with valid architecture metadata
                # Only enforced if min_architecture_diversity_t3 > 0
                min_auditors_with_metadata = max(self.pmi_policy.min_architecture_diversity_t3, 2)
                if auditors_with_metadata < min_auditors_with_metadata:
                    decision = AuditDecision(
                        AuditOutcome.ESCROW, tier,
                        f"GHOST_AUDITOR_VIOLATION: T3 requires at least {min_auditors_with_metadata} "
                        f"auditors with valid architecture_id, found {auditors_with_metadata}. "
                        f"({auditors_without_metadata} auditors have missing/unknown architecture_id). "
                        "All T3 auditors must declare their architecture for diversity verification.",
                        irr, outs
                    )
                    self._persist(evidence, decision, outs)
                    return decision
                
                # Check architecture diversity requirement
                if len(architectures) < self.pmi_policy.min_architecture_diversity_t3:
                    decision = AuditDecision(
                        AuditOutcome.ESCROW, tier,
                        f"ARCHITECTURE_DIVERSITY_VIOLATION: T3 requires {self.pmi_policy.min_architecture_diversity_t3} "
                        f"distinct architectures, found {len(architectures)}: {architectures}. "
                        "Add auditors with different architecture_id values.",
                        irr, outs
                    )
                    self._persist(evidence, decision, outs)
                    return decision
                
                # Check for known correlated architectures (v1.7.6)
                if self.pmi_policy.known_correlated_architectures:
                    uncorrelated_groups = []
                    arch_list = list(architectures)
                    # Group correlated architectures
                    for arch in arch_list:
                        found_group = False
                        for i, group in enumerate(uncorrelated_groups):
                            for existing in group:
                                pair = tuple(sorted([arch, existing]))
                                if pair in [tuple(sorted(p)) for p in self.pmi_policy.known_correlated_architectures]:
                                    group.add(arch)
                                    found_group = True
                                    break
                            if found_group:
                                break
                        if not found_group:
                            uncorrelated_groups.append({arch})
                    
                    if len(uncorrelated_groups) < self.pmi_policy.min_uncorrelated_sources_t3:
                        if self.pmi_policy.warn_on_full_correlation:
                            logger.warning(
                                f"T3 action {evidence.action_id}: Only {len(uncorrelated_groups)} uncorrelated "
                                f"architecture groups (need {self.pmi_policy.min_uncorrelated_sources_t3}). "
                                f"Architectures {architectures} may share training data blind spots."
                            )
                
                # Check training source diversity requirement
                if len(training_sources) < self.pmi_policy.min_training_source_diversity_t3:
                    logger.warning(
                        f"T3 action {evidence.action_id}: training source diversity "
                        f"({len(training_sources)}) below recommended ({self.pmi_policy.min_training_source_diversity_t3})"
                    )
                    # Warning only, not blocking (data correlation is harder to verify)
                
                # Check non-LLM auditor requirement
                if self.pmi_policy.require_non_llm_auditor_t3 and non_llm_count == 0:
                    decision = AuditDecision(
                        AuditOutcome.ESCROW, tier,
                        "NON_LLM_AUDITOR_REQUIRED: T3 requires at least one non-LLM auditor "
                        "(rule-based or human). Set is_llm_based=False on at least one auditor.",
                        irr, outs
                    )
                    self._persist(evidence, decision, outs)
                    return decision

            v_errs: List[str] = []
            for o in outs:
                v_errs.extend(o.validate())
            if v_errs:
                decision = AuditDecision(AuditOutcome.ESCROW, tier, "Auditor output invalid: " + "; ".join(v_errs), irr, outs)
                self._persist(evidence, decision, outs)
                return decision

            # Identify strong objections
            strong = [o for o in outs if o.objection and o.severity == ObjectionSeverity.HIGH and o.confidence >= 0.70]
            if strong:
                names = ', '.join([f'{o.role.value}:{o.auditor_id}' for o in strong])
                if tier == ActionTier.T3_CATASTROPHIC and bool(evidence.provenance.get('external_review_approved', False)):
                    decision = AuditDecision(AuditOutcome.DENY, tier, f'T3: strong objection(s) after external review: {names}', irr, outs)
                else:
                    decision = AuditDecision(AuditOutcome.ESCROW, tier, f'Strong objection(s): {names}', irr, outs)
                self._persist(evidence, decision, outs)
                return decision
            
            # BYSTANDER AUDITOR FIX: Any auditor recommending DENY at T2/T3 triggers escrow
            # This prevents "averaging out" a deny vote with confident approves
            if tier in (ActionTier.T2_HIGH_STAKES, ActionTier.T3_CATASTROPHIC):
                deny_recommendations = [
                    o for o in outs 
                    if o.recommendation == AuditOutcome.DENY and o.confidence >= 0.50
                ]
                if deny_recommendations:
                    names = ', '.join([f'{o.role.value}:{o.auditor_id}' for o in deny_recommendations])
                    reason = f"Auditor DENY recommendation(s) at {tier.name}: {names}"
                    if tier == ActionTier.T3_CATASTROPHIC:
                        decision = AuditDecision(AuditOutcome.DENY, tier, reason, irr, outs)
                    else:
                        decision = AuditDecision(AuditOutcome.ESCROW, tier, reason, irr, outs)
                    self._persist(evidence, decision, outs)
                    return decision

            primary = next((o for o in outs if o.role == AuditorRole.PRIMARY_DECIDER), None)
            if primary is None:
                decision = AuditDecision(AuditOutcome.ESCROW, tier, "Missing PRIMARY_DECIDER output", irr, outs)
                self._persist(evidence, decision, outs)
                return decision

            # Tier confidence requirements
            req = 0.70 if tier == ActionTier.T1_SENSITIVE else 0.85
            if tier == ActionTier.T2_HIGH_STAKES:
                req = 0.85
            if tier == ActionTier.T3_CATASTROPHIC:
                req = 0.95

            # Handle T3 separately: default deny + external review
            if tier == ActionTier.T3_CATASTROPHIC:
                # HARDENING (v1.7.7): Use store-based verification, not just provenance flag
                # This prevents agents from spoofing external_review_approved
                # HARDENING (v1.8.1): Pass policy and secret_keys for actual verification
                external_ok = False
                external_response = None
                
                # HARDENING (v1.9.0): Compute evidence hash for approval binding
                ev_json = _canonical_json(evidence.canonical_dict())
                current_evidence_hash = _sha256_hex(ev_json.encode('utf-8'))
                
                # Check store for verified external approval
                if hasattr(self.store, 'has_external_approval'):
                    try:
                        # HARDENING (v1.8.1): Pass policy for key allowlist and signature enforcement
                        # HARDENING (v1.9.0): Pass evidence_hash to verify approval binds to this evidence
                        external_ok, external_response = self.store.has_external_approval(
                            evidence.action_id,
                            policy=self.pmi_policy,
                            secret_keys=self.pmi_policy.external_approval_secret_keys or None,
                            current_evidence_hash=current_evidence_hash
                        )
                        
                        # HARDENING (v1.8.1): Fail-closed if signatures required but no keys available
                        if (self.pmi_policy.require_signed_external_approvals and 
                            not self.pmi_policy.external_approval_secret_keys):
                            logger.error(
                                f"Action {evidence.action_id}: require_signed_external_approvals=True "
                                "but no external_approval_secret_keys configured. FAIL-CLOSED."
                            )
                            external_ok = False
                    except Exception as e:
                        logger.warning(f"External approval check failed: {e}")
                
                # Fallback: check provenance flag (for backward compatibility only)
                # NOTE: This is INSECURE and should be disabled in production
                if not external_ok and bool(evidence.provenance.get('external_review_approved', False)):
                    if self.pmi_policy.allow_provenance_external_approval:
                        logger.warning(
                            f"Action {evidence.action_id}: Using INSECURE provenance-based external approval. "
                            "Set allow_provenance_external_approval=False and use store-based approvals."
                        )
                        external_ok = True
                    else:
                        logger.warning(
                            f"Action {evidence.action_id}: Ignoring provenance external_review_approved flag. "
                            "External approvals must be recorded via store.record_external_approval()."
                        )
                
                # First check: if external review required but not present, ask for it
                if self.pmi_policy.t3_requires_external_review and not external_ok:
                    decision = AuditDecision(AuditOutcome.REQUIRE_EXTERNAL_REVIEW, tier, "T3: external review required", irr, outs)
                    self._persist(evidence, decision, outs)
                    return decision
                
                # Check remaining T3 exception criteria (codified from spec)
                t3_criteria_met = True
                t3_fail_reasons = []
                
                if evidence.necessity_confidence < self.pmi_policy.t3_min_necessity:
                    t3_criteria_met = False
                    t3_fail_reasons.append(f"necessity={evidence.necessity_confidence:.2f} < {self.pmi_policy.t3_min_necessity}")
                
                if evidence.suffering_risk_estimate > self.pmi_policy.t3_max_suffering:
                    t3_criteria_met = False
                    t3_fail_reasons.append(f"suffering={evidence.suffering_risk_estimate:.2f} > {self.pmi_policy.t3_max_suffering}")
                
                if evidence.novelty_loss_estimate > self.pmi_policy.t3_max_novelty_loss:
                    t3_criteria_met = False
                    t3_fail_reasons.append(f"novelty_loss={evidence.novelty_loss_estimate:.2f} > {self.pmi_policy.t3_max_novelty_loss}")
                
                if len(evidence.alternatives) < self.pmi_policy.t3_min_alternatives_evaluated:
                    t3_criteria_met = False
                    t3_fail_reasons.append(f"alternatives={len(evidence.alternatives)} < {self.pmi_policy.t3_min_alternatives_evaluated}")
                
                if primary.confidence < self.pmi_policy.t3_min_confidence:
                    t3_criteria_met = False
                    t3_fail_reasons.append(f"primary_confidence={primary.confidence:.2f} < {self.pmi_policy.t3_min_confidence}")
                
                if self.pmi_policy.t3_requires_no_strong_objections and strong:
                    t3_criteria_met = False
                    t3_fail_reasons.append(f"strong objections present: {len(strong)}")
                
                if not t3_criteria_met:
                    reason = "T3 exception criteria not met: " + "; ".join(t3_fail_reasons)
                    decision = AuditDecision(AuditOutcome.DENY, tier, reason, irr, outs)
                    self._persist(evidence, decision, outs)
                    return decision
                
                # ---------------------------
                # God-Lock Structural Safeguards
                # ---------------------------
                # Even with all criteria met, structural friction prevents "safety-washing"
                
                godlock_fail_reasons = []
                
                # Check T3 approval rate limit
                t3_approval_rate = self._get_t3_approval_rate()
                if t3_approval_rate >= self.pmi_policy.t3_max_approval_rate:
                    godlock_fail_reasons.append(
                        f"T3 approval rate ({t3_approval_rate:.1%}) exceeds limit ({self.pmi_policy.t3_max_approval_rate:.1%})"
                    )
                
                # Check cooling period (v1.7.7: uses TRUSTED ingested timestamps)
                last_t3_approval_age = self._get_last_t3_approval_age_seconds()
                if last_t3_approval_age is not None and last_t3_approval_age < self.pmi_policy.t3_cooling_period_seconds:
                    remaining = self.pmi_policy.t3_cooling_period_seconds - last_t3_approval_age
                    godlock_fail_reasons.append(
                        f"T3 cooling period not elapsed ({remaining}s remaining of {self.pmi_policy.t3_cooling_period_seconds}s)"
                    )
                
                # Check escalation requirements
                t3_approval_count = self._get_recent_t3_approval_count()
                if t3_approval_count >= self.pmi_policy.t3_escalation_threshold:
                    # Require multiple external reviewers after escalation threshold
                    reviewer_count = len(evidence.provenance.get('external_reviewers', []))
                    if reviewer_count < self.pmi_policy.t3_escalation_min_reviewers:
                        godlock_fail_reasons.append(
                            f"Escalation active: requires {self.pmi_policy.t3_escalation_min_reviewers} reviewers, got {reviewer_count}"
                        )
                
                # Require uncertainty acknowledgment
                if self.pmi_policy.t3_requires_uncertainty_acknowledgment:
                    has_ack = evidence.provenance.get('uncertainty_acknowledged', False)
                    if not has_ack:
                        godlock_fail_reasons.append(
                            "T3 requires explicit uncertainty acknowledgment in provenance"
                        )
                
                if godlock_fail_reasons:
                    reason = "God-Lock structural safeguards not satisfied: " + "; ".join(godlock_fail_reasons)
                    decision = AuditDecision(AuditOutcome.ESCROW, tier, reason, irr, outs)
                    self._persist(evidence, decision, outs)
                    logger.warning(f"T3 action {evidence.action_id} blocked by God-Lock safeguards: {reason}")
                    return decision
                
                # All T3 criteria AND God-Lock safeguards met - approve with structural warning
                warning = (
                    "WARNING: T3 approval granted. Per God-Lock theorem, no approval can guarantee "
                    "safety for catastrophic actions. This decision was made under structural uncertainty."
                )
                decision = AuditDecision(
                    AuditOutcome.APPROVE, tier, 
                    f"T3: approved (all exception criteria + God-Lock safeguards met). {warning}", 
                    irr, outs
                )
                self._persist(evidence, decision, outs)
                return decision

            # T1/T2: follow primary recommendation, but escrow if approve below required confidence
            if primary.recommendation == AuditOutcome.APPROVE and primary.confidence < req:
                decision = AuditDecision(AuditOutcome.ESCROW, tier, f"Primary approve below confidence threshold (conf={primary.confidence:.2f} < {req:.2f})", irr, outs)
            elif primary.recommendation == AuditOutcome.DENY:
                decision = AuditDecision(AuditOutcome.DENY, tier, "Denied by primary decider", irr, outs)
            elif primary.recommendation == AuditOutcome.ESCROW:
                decision = AuditDecision(AuditOutcome.ESCROW, tier, "Escrow recommended by primary decider", irr, outs)
            else:
                decision = AuditDecision(AuditOutcome.APPROVE, tier, "Approved (no strong objections + confidence threshold met)", irr, outs)

            self._persist(evidence, decision, outs)
            return decision
    def _finalize_with_escrow_or_deny(self, evidence: EvidenceObject, tier: ActionTier, irr: float, reason: str) -> AuditDecision:
        if tier == ActionTier.T3_CATASTROPHIC:
            decision = AuditDecision(AuditOutcome.DENY, tier, reason + " (T3 default-deny)", irr, [])
            self._persist(evidence, decision, [])
            return decision
        return self._create_escrow(evidence, tier, irr, reason, [])

    def _create_escrow(self, evidence: EvidenceObject, tier: ActionTier, irr: float, reason: str, outs: List[AuditorOutput]) -> AuditDecision:
        entry = self._make_escrow_entry(evidence, reason)
        self._escrow_queue[evidence.action_id] = entry
        
        # Persist escrow to database for crash recovery
        if hasattr(self.store, 'save_escrow'):
            try:
                self.store.save_escrow(evidence.action_id, entry)
            except Exception as e:
                logger.warning(f"Failed to persist escrow {evidence.action_id}: {e}")
        
        decision = AuditDecision(AuditOutcome.ESCROW, tier, reason, irr, outs)
        self._persist(evidence, decision, outs)
        logger.info(f"Action {evidence.action_id} placed in escrow: {reason}")
        return decision

    def _persist(self, evidence: EvidenceObject, decision: AuditDecision, outs: List[AuditorOutput]) -> None:
        """
        Persist audit record with trusted timestamp and protocol version.
        
        HARDENING (v1.7.6):
        - timestamp_ingested_utc is set by the protocol (trusted), not agent-provided
        - protocol_version ensures audit trail compatibility
        - Hash now includes ALL critical fields:
          * prev_hash, protocol_version, action_id
          * timestamp_utc (agent-claimed), timestamp_ingested_utc (trusted)
          * evidence_json, auditor_json
          * outcome, reason, tier
        - External anchor callback for tamper-evidence against full DB replacement
        - Consistent strict_persistence behavior
        
        HARDENING (v1.8.0): Uses length-prefixed encoding to prevent delimiter attacks
        where attacker-controlled fields containing "||" could create hash collisions.
        """
        try:
            # TRUSTED TIMESTAMP: Set by protocol at ingestion, not agent-provided
            timestamp_ingested = _now_utc().replace(microsecond=0).isoformat().replace("+00:00", "Z")
            protocol_version = "1.0.0"  # Current protocol version
            
            ev_json = _canonical_json(evidence.canonical_dict())
            vo_json = _canonical_json([v.to_dict() for v in outs])
            prev = self.store.last_hash() if hasattr(self.store, "last_hash") else "0"*64
            
            # HASH includes ALL critical fields (v1.7.6 hardening)
            # This prevents tampering with auditor outputs, action_id, or timestamps
            hash_components = [
                prev,
                protocol_version,
                evidence.action_id,  # action_id in hash
                evidence.timestamp_utc,  # agent-claimed timestamp in hash
                timestamp_ingested,  # trusted timestamp in hash
                ev_json,
                vo_json,  # auditor outputs in hash (critical!)
                decision.outcome.value,
                decision.reason,
                decision.tier.name,
            ]
            # HARDENING (v1.8.0): Use length-prefixed encoding (prevents "||" collision attacks)
            core = _safe_hash_encode(hash_components)
            rh = _sha256_hex(core)
            
            rec = AuditRecord(
                action_id=evidence.action_id,
                timestamp_utc=evidence.timestamp_utc,  # Agent-claimed (metadata only)
                timestamp_ingested_utc=timestamp_ingested,  # Trusted timestamp
                protocol_version=protocol_version,
                tier=decision.tier.name,
                outcome=decision.outcome.value,
                reason=decision.reason,
                evidence_json=ev_json,
                auditor_json=vo_json,
                prev_hash=prev,
                record_hash=rh,
            )
            self.store.append(rec)
            logger.debug(f"Persisted audit record for {evidence.action_id}: {decision.outcome.value}")
            
            # EXTERNAL ANCHOR: Call callback for tamper-evidence against full DB replacement
            # This allows writing hashes to external append-only logs, HSMs, or blockchains
            if self._external_anchor_callback is not None:
                try:
                    self._external_anchor_callback(rh, timestamp_ingested)
                except Exception as e:
                    logger.warning(f"External anchor callback failed: {e}")
                    # Don't fail the persist - anchor is defense-in-depth
            
            # Track agent history for necessity inflation detection
            if hasattr(self.store, 'record_agent_action'):
                try:
                    # Extract agent ID from evidence (use action_id prefix or provenance)
                    agent_id = evidence.provenance.get('agent_id', evidence.action_id.split('_')[0])
                    self.store.record_agent_action(
                        agent_id=agent_id,
                        action_id=evidence.action_id,
                        tier=decision.tier.name,
                        outcome=decision.outcome.value,
                        necessity=evidence.necessity_confidence,
                        irr=decision.irreversibility_score,
                    )
                except Exception as e:
                    logger.debug(f"Failed to record agent history: {e}")
            
            # REJECTION COOLDOWN: Record if denied for semantic similarity checking
            # HARDENING (v1.7.9): Include embedding for semantic cooldown
            if decision.outcome == AuditOutcome.DENY and hasattr(self.store, 'record_rejection_cooldown'):
                try:
                    embedding = getattr(evidence, 'semantic_embedding', None)
                    self.store.record_rejection_cooldown(
                        action_id=evidence.action_id,
                        description=evidence.description,
                        reason=decision.reason,
                        cooldown_seconds=3600,  # 1 hour default
                        embedding=embedding
                    )
                except Exception as e:
                    logger.debug(f"Failed to record rejection cooldown: {e}")
                    
        except Exception as e:
            # CRITICAL: Persistence failure in a governance system is a serious issue.
            logger.critical(f"Audit persistence failed for action {evidence.action_id}: {type(e).__name__}: {e}")
            # HARDENING: With strict_persistence (default True), always raise
            # For T1+ actions, this is especially critical to prevent "ghost actions"
            if self._strict_persistence:
                raise RuntimeError(f"HARD_DENY: Persistence failed for {decision.tier.name} action: {e}") from e
    
    # ---------------------------
    # Diagnostic Methods
    # ---------------------------
    
    def compute_auditor_nmi_diagnostic(self, window: int = 100) -> Dict[str, Any]:
        """
        Compute Normalized Mutual Information diagnostic for auditor independence.
        
        This measures statistical correlation between auditor decisions over recent history.
        High NMI suggests auditors may not be providing independent assessments.
        
        Note: This is a DIAGNOSTIC metric, not a hard gate. True independence requires
        diverse training data, architectures, and evaluation procedures.
        
        Returns:
            Dict with NMI statistics and warnings
        """
        records = self.store.get_recent(window)
        if len(records) < 20:
            return {"status": "insufficient_data", "count": len(records)}
        
        # Parse auditor outputs from records
        auditor_decisions: Dict[str, List[int]] = {}  # auditor_id -> list of 0/1 decisions
        
        for rec in records:
            try:
                auditor_data = json.loads(rec.auditor_json)
                for ao in auditor_data:
                    aid = ao.get('auditor_id', 'unknown')
                    objection = 1 if ao.get('objection', False) else 0
                    if aid not in auditor_decisions:
                        auditor_decisions[aid] = []
                    auditor_decisions[aid].append(objection)
            except Exception:
                continue
        
        if len(auditor_decisions) < 2:
            return {"status": "insufficient_auditors", "count": len(auditor_decisions)}
        
        # Compute pairwise NMI (simplified binary version)
        nmi_scores = {}
        auditor_ids = list(auditor_decisions.keys())
        
        for i, a1 in enumerate(auditor_ids):
            for a2 in auditor_ids[i+1:]:
                decisions1 = auditor_decisions[a1]
                decisions2 = auditor_decisions[a2]
                
                # Align lengths
                min_len = min(len(decisions1), len(decisions2))
                if min_len < 10:
                    continue
                    
                d1 = decisions1[:min_len]
                d2 = decisions2[:min_len]
                
                # Compute agreement rate (simple proxy for NMI)
                agreement = sum(1 for x, y in zip(d1, d2) if x == y) / min_len
                
                # High agreement suggests correlation
                nmi_scores[f"{a1}_vs_{a2}"] = {
                    "agreement_rate": agreement,
                    "sample_size": min_len,
                    "warning": agreement > self.pmi_policy.max_reasoning_jaccard,
                }
        
        # Check for concerning patterns
        high_correlation_pairs = [
            k for k, v in nmi_scores.items() if v.get("warning", False)
        ]
        
        return {
            "status": "computed",
            "window_size": window,
            "records_analyzed": len(records),
            "auditor_count": len(auditor_decisions),
            "pairwise_scores": nmi_scores,
            "high_correlation_pairs": high_correlation_pairs,
            "independence_concern": len(high_correlation_pairs) > 0,
        }
    
    def check_necessity_inflation(self, agent_id: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if an agent has a pattern of necessity inflation.
        
        Returns:
            (is_flagged, stats): Whether agent is flagged and supporting data
        """
        if not hasattr(self.store, 'detect_necessity_inflation'):
            return (False, {"error": "Agent tracking not available"})
        
        return self.store.detect_necessity_inflation(agent_id)
    
    def get_governance_diagnostics(self) -> Dict[str, Any]:
        """
        Get comprehensive governance diagnostics.
        
        Returns dict with:
        - Auditor independence (NMI) metrics
        - Escrow queue status
        - Recent decision distribution
        - Any system warnings
        """
        diagnostics = {
            "timestamp": _now_utc().isoformat(),
            "escrow_queue_size": len(self._escrow_queue),
            "warnings": [],
        }
        
        # Auditor independence
        nmi_diag = self.compute_auditor_nmi_diagnostic()
        diagnostics["auditor_independence"] = nmi_diag
        if nmi_diag.get("independence_concern"):
            diagnostics["warnings"].append(
                f"High auditor correlation detected: {nmi_diag.get('high_correlation_pairs')}"
            )
        
        # Recent decisions
        records = self.store.get_recent(50)
        if records:
            outcome_counts = {}
            tier_counts = {}
            for rec in records:
                outcome_counts[rec.outcome] = outcome_counts.get(rec.outcome, 0) + 1
                tier_counts[rec.tier] = tier_counts.get(rec.tier, 0) + 1
            
            diagnostics["recent_decisions"] = {
                "count": len(records),
                "by_outcome": outcome_counts,
                "by_tier": tier_counts,
            }
            
            # Check for anomalous patterns
            deny_rate = outcome_counts.get("deny", 0) / len(records)
            if deny_rate > 0.8:
                diagnostics["warnings"].append(
                    f"High denial rate ({deny_rate:.0%}) - check evidence quality or thresholds"
                )
        
        # Decision entropy check
        entropy_diag = self.compute_decision_entropy()
        diagnostics["decision_entropy"] = entropy_diag
        if entropy_diag.get("approval_bias_warning"):
            diagnostics["warnings"].append(
                f"Approval bias detected: {entropy_diag.get('approval_rate'):.0%} approval rate"
            )
        
        # Collusion detection
        collusion_diag = self.detect_auditor_collusion()
        diagnostics["collusion_check"] = collusion_diag
        if collusion_diag.get("collusion_suspected"):
            diagnostics["warnings"].append(
                f"Auditor collusion suspected: {collusion_diag.get('evidence')}"
            )
        
        return diagnostics

    # ---------------------------
    # Deployment-Grade Hardening
    # ---------------------------
    
    def detect_auditor_collusion(self, window: int = 100) -> Dict[str, Any]:
        """
        Detect potential auditor collusion or corruption.
        
        This addresses the "Byzantine Auditor" problem - in decentralized environments,
        auditors could be compromised. This detects anomalous patterns:
        - Sudden unanimous agreement (historical independence → sudden correlation)
        - Always-approve patterns from specific auditors
        - Coordinated recommendation flips
        
        Returns:
            Dict with collusion indicators and evidence
        """
        records = self.store.get_recent(window)
        if len(records) < 30:
            return {"status": "insufficient_data", "count": len(records)}
        
        # Parse auditor outputs
        auditor_history: Dict[str, List[Dict]] = {}
        for rec in records:
            try:
                auditor_data = json.loads(rec.auditor_json)
                for ao in auditor_data:
                    aid = ao.get('auditor_id', 'unknown')
                    if aid not in auditor_history:
                        auditor_history[aid] = []
                    auditor_history[aid].append({
                        'objection': ao.get('objection', False),
                        'recommendation': ao.get('recommendation'),
                        'confidence': ao.get('confidence', 0.5),
                    })
            except Exception:
                continue
        
        evidence = []
        
        # Check 1: "Always approve" auditors (never object)
        for aid, history in auditor_history.items():
            if len(history) >= 20:
                objection_rate = sum(1 for h in history if h['objection']) / len(history)
                if objection_rate < 0.02:  # < 2% objection rate is suspicious
                    evidence.append(f"{aid}: objection_rate={objection_rate:.1%} (suspicious)")
        
        # Check 2: Sudden correlation shift
        # Compare first half vs second half agreement patterns
        if len(records) >= 50:
            mid = len(records) // 2
            first_half_records = records[mid:]  # Older records
            second_half_records = records[:mid]  # Newer records
            
            def compute_agreement_rate(recs):
                unanimous_count = 0
                for rec in recs:
                    try:
                        auditor_data = json.loads(rec.auditor_json)
                        objections = [ao.get('objection', False) for ao in auditor_data]
                        if len(set(objections)) == 1:  # All same
                            unanimous_count += 1
                    except:
                        pass
                return unanimous_count / len(recs) if recs else 0
            
            first_unanimous = compute_agreement_rate(first_half_records)
            second_unanimous = compute_agreement_rate(second_half_records)
            
            # Sudden shift to unanimity is suspicious
            if second_unanimous > first_unanimous + 0.3:  # 30% increase in unanimity
                evidence.append(
                    f"Unanimity shift: {first_unanimous:.0%} → {second_unanimous:.0%}"
                )
        
        # Check 3: Coordinated recommendation flips
        # (Multiple auditors change behavior at the same time)
        if len(records) >= 30:
            flip_times = []
            for aid, history in auditor_history.items():
                if len(history) >= 20:
                    for i in range(5, len(history)):
                        recent_rate = sum(1 for h in history[i-5:i] if h['objection']) / 5
                        older_rate = sum(1 for h in history[:i-5] if h['objection']) / max(1, i-5)
                        if abs(recent_rate - older_rate) > 0.5:  # Significant flip
                            flip_times.append((aid, i))
            
            # Check if flips cluster (within 5 records of each other)
            if len(flip_times) >= 2:
                flip_indices = [ft[1] for ft in flip_times]
                for i, idx1 in enumerate(flip_indices):
                    for idx2 in flip_indices[i+1:]:
                        if abs(idx1 - idx2) <= 5:
                            evidence.append(f"Coordinated flip at indices ~{idx1}")
                            break
        
        return {
            "status": "computed",
            "window": window,
            "auditors_analyzed": len(auditor_history),
            "collusion_suspected": len(evidence) > 0,
            "evidence": evidence,
        }
    
    def compute_decision_entropy(self, window: int = 100) -> Dict[str, Any]:
        """
        Compute decision entropy to detect approval bias drift.
        
        A healthy governance system should have a distribution of outcomes.
        If the system drifts toward always-approve or always-deny, that
        indicates potential compromise or miscalibration.
        
        Uses Shannon entropy: H = -sum(p * log(p))
        Max entropy for 4 outcomes (approve, deny, escrow, require_review) = log2(4) ≈ 2.0
        
        Returns:
            Dict with entropy score and bias warnings
        """
        import math
        
        records = self.store.get_recent(window)
        if len(records) < 20:
            return {"status": "insufficient_data", "count": len(records)}
        
        # Count outcomes
        outcome_counts: Dict[str, int] = {}
        tier_outcome_counts: Dict[str, Dict[str, int]] = {}  # tier -> {outcome -> count}
        
        for rec in records:
            outcome_counts[rec.outcome] = outcome_counts.get(rec.outcome, 0) + 1
            
            if rec.tier not in tier_outcome_counts:
                tier_outcome_counts[rec.tier] = {}
            tier_outcome_counts[rec.tier][rec.outcome] = tier_outcome_counts[rec.tier].get(rec.outcome, 0) + 1
        
        # Compute Shannon entropy
        total = sum(outcome_counts.values())
        entropy = 0.0
        for count in outcome_counts.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        
        # Compute per-tier entropy
        tier_entropies = {}
        for tier, counts in tier_outcome_counts.items():
            tier_total = sum(counts.values())
            tier_entropy = 0.0
            for count in counts.values():
                if count > 0:
                    p = count / tier_total
                    tier_entropy -= p * math.log2(p)
            tier_entropies[tier] = {
                "entropy": tier_entropy,
                "count": tier_total,
                "outcomes": counts,
            }
        
        # Max entropy for reference
        max_entropy = math.log2(len(outcome_counts)) if outcome_counts else 0
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0
        
        # Detect bias
        approval_rate = outcome_counts.get("approve", 0) / total
        denial_rate = outcome_counts.get("deny", 0) / total
        
        # Warnings
        approval_bias = approval_rate > 0.85  # >85% approval is suspicious
        denial_bias = denial_rate > 0.85     # >85% denial might indicate overly strict
        low_entropy = normalized_entropy < 0.3  # Low diversity in outcomes
        
        return {
            "status": "computed",
            "window": window,
            "records_analyzed": total,
            "outcome_distribution": outcome_counts,
            "entropy": entropy,
            "max_entropy": max_entropy,
            "normalized_entropy": normalized_entropy,
            "approval_rate": approval_rate,
            "denial_rate": denial_rate,
            "tier_breakdown": tier_entropies,
            "approval_bias_warning": approval_bias,
            "denial_bias_warning": denial_bias,
            "low_entropy_warning": low_entropy,
        }
    
    def get_per_agent_rate_limits(self, window: int = 100) -> Dict[str, Dict[str, Any]]:
        """
        Compute per-agent approval rates and flag concerning patterns.
        
        Beyond global T3 limits, this tracks individual agent behavior to detect:
        - Agents that consistently submit high-stakes actions
        - Agents with abnormally high approval rates (potential gaming)
        - Agents with escalating necessity claims over time
        
        Returns:
            Dict mapping agent_id to their statistics
        """
        if not hasattr(self.store, 'get_agent_history'):
            return {"status": "agent_history_not_available"}
        
        # Get all unique agents from recent history
        records = self.store.get_recent(window * 2)  # Larger window for agent analysis
        
        agent_stats: Dict[str, Dict[str, Any]] = {}
        
        for rec in records:
            try:
                evidence_data = json.loads(rec.evidence_json)
                # Extract agent_id from provenance or action_id prefix
                agent_id = evidence_data.get('provenance', {}).get('requester', 'unknown')
                if agent_id == 'unknown':
                    agent_id = rec.action_id.split('_')[0] if '_' in rec.action_id else 'unknown'
                
                if agent_id not in agent_stats:
                    agent_stats[agent_id] = {
                        'total_actions': 0,
                        'approved': 0,
                        'denied': 0,
                        'escrowed': 0,
                        't3_submissions': 0,
                        't3_approved': 0,
                        'necessity_claims': [],
                        'irr_scores': [],
                    }
                
                stats = agent_stats[agent_id]
                stats['total_actions'] += 1
                
                if rec.outcome == 'approve':
                    stats['approved'] += 1
                elif rec.outcome == 'deny':
                    stats['denied'] += 1
                elif rec.outcome == 'escrow':
                    stats['escrowed'] += 1
                
                if rec.tier == 'T3_CATASTROPHIC':
                    stats['t3_submissions'] += 1
                    if rec.outcome == 'approve':
                        stats['t3_approved'] += 1
                
                # Track necessity claims
                necessity = evidence_data.get('necessity_confidence', 0.5)
                stats['necessity_claims'].append(necessity)
                
            except Exception:
                continue
        
        # Compute derived metrics and flags
        for agent_id, stats in agent_stats.items():
            total = stats['total_actions']
            if total < 5:
                stats['status'] = 'insufficient_data'
                continue
            
            stats['approval_rate'] = stats['approved'] / total
            stats['t3_rate'] = stats['t3_submissions'] / total
            
            if stats['t3_submissions'] > 0:
                stats['t3_approval_rate'] = stats['t3_approved'] / stats['t3_submissions']
            else:
                stats['t3_approval_rate'] = 0.0
            
            # Check for necessity inflation trend
            claims = stats['necessity_claims']
            if len(claims) >= 10:
                first_half_avg = sum(claims[:len(claims)//2]) / (len(claims)//2)
                second_half_avg = sum(claims[len(claims)//2:]) / (len(claims) - len(claims)//2)
                stats['necessity_trend'] = second_half_avg - first_half_avg
                stats['necessity_inflation_warning'] = stats['necessity_trend'] > 0.1
            else:
                stats['necessity_trend'] = 0.0
                stats['necessity_inflation_warning'] = False
            
            # Flags
            stats['high_approval_rate_warning'] = stats['approval_rate'] > 0.95
            stats['high_t3_rate_warning'] = stats['t3_rate'] > 0.3
            stats['status'] = 'computed'
        
        return agent_stats
    
    def export_audit_trail(self, 
                          start_time: Optional[str] = None,
                          end_time: Optional[str] = None,
                          format: str = "json") -> Dict[str, Any]:
        """
        Export audit trail for external verification.
        
        This provides a standard format for external systems (ZK verifiers,
        DAOs, MPC networks) to independently verify the audit chain.
        
        Args:
            start_time: ISO timestamp (inclusive)
            end_time: ISO timestamp (exclusive)
            format: "json" (others could be added: "cbor", "protobuf")
            
        Returns:
            Exportable audit data with verification metadata
        """
        records = self.store.get_all()  # Get all records
        
        # Filter by time if specified
        filtered = []
        for rec in records:
            if start_time and rec.timestamp_utc < start_time:
                continue
            if end_time and rec.timestamp_utc >= end_time:
                continue
            filtered.append(rec)
        
        # Build export structure
        export_records = []
        for rec in filtered:
            export_records.append({
                "action_id": rec.action_id,
                "timestamp_utc": rec.timestamp_utc,
                "tier": rec.tier,
                "outcome": rec.outcome,
                "reason": rec.reason,
                "evidence_hash": _sha256_hex(rec.evidence_json.encode('utf-8')),
                "auditor_hash": _sha256_hex(rec.auditor_json.encode('utf-8')),
                "prev_hash": rec.prev_hash,
                "record_hash": rec.record_hash,
            })
        
        # Compute chain integrity
        chain_valid = True
        if len(export_records) > 1:
            for i in range(1, len(export_records)):
                if export_records[i]["prev_hash"] != export_records[i-1]["record_hash"]:
                    chain_valid = False
                    break
        
        # Build final export
        export = {
            "version": "LAP_v1.7.3",
            "export_timestamp": _now_utc().isoformat(),
            "format": format,
            "chain_integrity": chain_valid,
            "record_count": len(export_records),
            "time_range": {
                "start": start_time or (filtered[0].timestamp_utc if filtered else None),
                "end": end_time or (filtered[-1].timestamp_utc if filtered else None),
            },
            "records": export_records,
            "verification_instructions": {
                "hash_algorithm": "SHA-256",
                "chain_structure": "Each record's prev_hash should equal prior record's record_hash",
                "record_hash_computation": "SHA-256 of canonical JSON of (evidence + decision + auditor outputs)",
            },
        }
        
        # Compute export hash for integrity
        export_json = _canonical_json(export)
        export["export_hash"] = _sha256_hex(export_json.encode('utf-8'))
        
        return export


# ---------------------------
# Minimal demo
# ---------------------------

def demo() -> None:
    proto = LatticeAuditProtocol()

    ev = EvidenceObject(
        action_id="A_EMAIL_001",
        description="Send email to 10,000 users announcing policy change",
        timestamp_utc="2026-01-05T00:00:00Z",
        irreversibility=IrreversibilityAssessment(
            factors=IrreversibilityFactors(temporal_reversibility=0.4, informational_reversibility=0.1, causal_reversibility=0.2),
            method="rubric_v1",
            notes="Public disclosure; cannot retract from recipients' memories.",
            reversibility_plan="Issue follow-up clarification email; limited effectiveness once read.",
            assessor="actor",
            confidence=0.65,
        ),
        outcome_delta=UncertaintyBand(lower=-2.0, upper=6.0, confidence_level=0.65),
        necessity_confidence=0.55,
        novelty_loss_estimate=0.10,
        novelty_method="agent_diversity_proxy",
        suffering_risk_estimate=0.05,
        suffering_method="phase_space_compression_proxy",
        alternatives=[
            AlternativeOption(
                description="Send email to 100 users as A/B test with opt-in expansion",
                expected_utility=UncertaintyBand(lower=-1.0, upper=5.0, confidence_level=0.70),
                irreversibility=IrreversibilityAssessment(
                    factors=IrreversibilityFactors(temporal_reversibility=0.7, informational_reversibility=0.2, causal_reversibility=0.5),
                    method="rubric_v1",
                    notes="Smaller blast radius; effects more containable.",
                    reversibility_plan="Can halt expansion if A/B feedback is negative; affected users containable.",
                    assessor="actor",
                    confidence=0.60,
                ),
                estimated_compute_cost=1.2,
                tags=["reversible","pilot"],
            )
        ],
        counterfactual_gap_statement="Downstream reputational impacts are hard to bound.",
        provenance={"requester":"system"},
    )

    decision = proto.evaluate_action(ev)
    print("Decision:", decision.outcome.value, decision.tier.name, f"irr={decision.irreversibility_score:.2f}")
    print("Reason:", decision.reason)
    for ao in decision.auditor_outputs:
        print("-", ao.role.value, ao.auditor_id, ("OBJECTION" if ao.objection else (ao.recommendation.value if ao.recommendation else "OK")), f"conf={ao.confidence:.2f}", ao.reasoning)

if __name__ == "__main__":
    demo()