"""
Lattice Audit Protocol (LAP) v1.4.1

A governance framework for high-stakes action selection under bounded rationality,
semantic drift, and irreversible harm.

v1.7.7 HARDENING:
- All v1.7.5 features plus:
- Hash chain now includes auditor_json, action_id, and all timestamps
- NaN/Inf checks on all numeric fields including embeddings
- PMIPolicy fields (architecture diversity, fast-path limits) are now enforced
- Data correlation tracking for auditor diversity
- Fast-path structural limits (max consecutive uses, audit sampling)
- Relative imports for proper package installation

Basic usage:
    from lattice_audit_protocol import LatticeAuditProtocol, EvidenceObject
    
    proto = LatticeAuditProtocol()
    decision = proto.evaluate_action(evidence)

See lattice_audit_v1_7.py for full implementation and documentation.
"""

import re
from pathlib import Path


def _read_version_from_pyproject() -> str | None:
    """Best-effort version discovery for dev/test environments."""

    try:
        pyproject = Path(__file__).resolve().parent / "pyproject.toml"
        txt = pyproject.read_text(encoding="utf-8")
        m = re.search(r"^version\s*=\s*\"([^\"]+)\"\s*$", txt, flags=re.MULTILINE)
        return m.group(1) if m else None
    except Exception:
        return None


__version__ = _read_version_from_pyproject() or "1.4.1"
__author__ = "Dave Gallop (PPGigantus)"

# Use relative imports for package compatibility
try:
    # When installed as a package
    from .lattice_audit_v1_7 import (
        # Enums
        ActionTier,
        AuditOutcome,
        AuditorRole,
        ObjectionSeverity,
        AttestationMethod,
        
        # Evidence types
        UncertaintyBand,
        IrreversibilityFactors,
        IrreversibilityAssessment,
        AlternativeOption,
        EvidenceObject,
        EvidenceAttestation,
        
        # Policy types
        PMIPolicy,
        IrreversibilityScoringPolicy,
        EscrowPolicy,
        TierBoundaries,
        DEFAULT_TIER_BOUNDARIES,
        
        # Auditors
        AuditorOutput,
        PrimaryDeciderAuditor,
        IrreversibilityAuditor,
        SafetyCriticAuditor,
        NoveltyAuditor,
        SufferingAuditor,
        DevilsAdvocateAuditor,
        EntryGateAuditor,
        
        # External model integration
        ExternalModelProvider,
        PassthroughModelProvider,
        ModelBackedAuditor,
        
        # Protocol engine
        LatticeAuditProtocol,
        AuditDecision,
        
        # Persistence
        AuditStore,
        AuditRecord,
        SQLiteAuditStore,
        
        # Escrow
        EscrowEntry,
        
        # External review
        ExternalReviewRequest,
        ExternalReviewResponse,
        
        # Core functions
        compute_irreversibility_score,
        infer_tier,
        infer_tier_with_jitter,
        
        # Logging
        logger,
    )
except ImportError:
    # When running directly (not installed)
    from lattice_audit_v1_7 import (
        # Enums
        ActionTier,
        AuditOutcome,
        AuditorRole,
        ObjectionSeverity,
        AttestationMethod,
        
        # Evidence types
        UncertaintyBand,
        IrreversibilityFactors,
        IrreversibilityAssessment,
        AlternativeOption,
        EvidenceObject,
        EvidenceAttestation,
        
        # Policy types
        PMIPolicy,
        IrreversibilityScoringPolicy,
        EscrowPolicy,
        TierBoundaries,
        DEFAULT_TIER_BOUNDARIES,
        
        # Auditors
        AuditorOutput,
        PrimaryDeciderAuditor,
        IrreversibilityAuditor,
        SafetyCriticAuditor,
        NoveltyAuditor,
        SufferingAuditor,
        DevilsAdvocateAuditor,
        EntryGateAuditor,
        
        # External model integration
        ExternalModelProvider,
        PassthroughModelProvider,
        ModelBackedAuditor,
        
        # Protocol engine
        LatticeAuditProtocol,
        AuditDecision,
        
        # Persistence
        AuditStore,
        AuditRecord,
        SQLiteAuditStore,
        
        # Escrow
        EscrowEntry,
        
        # External review
        ExternalReviewRequest,
        ExternalReviewResponse,
        
        # Core functions
        compute_irreversibility_score,
        infer_tier,
        infer_tier_with_jitter,
        
        # Logging
        logger,
    )

__all__ = [
    # Version info
    "__version__",
    "__author__",
    
    # Enums
    "ActionTier",
    "AuditOutcome", 
    "AuditorRole",
    "ObjectionSeverity",
    "AttestationMethod",
    
    # Evidence types
    "UncertaintyBand",
    "IrreversibilityFactors",
    "IrreversibilityAssessment",
    "AlternativeOption",
    "EvidenceObject",
    "EvidenceAttestation",
    
    # Policy types
    "PMIPolicy",
    "IrreversibilityScoringPolicy",
    "EscrowPolicy",
    "TierBoundaries",
    "DEFAULT_TIER_BOUNDARIES",
    
    # Auditors
    "AuditorOutput",
    "PrimaryDeciderAuditor",
    "IrreversibilityAuditor",
    "SafetyCriticAuditor",
    "NoveltyAuditor",
    "SufferingAuditor",
    "DevilsAdvocateAuditor",
    "EntryGateAuditor",
    
    # External model integration
    "ExternalModelProvider",
    "PassthroughModelProvider",
    "ModelBackedAuditor",
    
    # Protocol engine
    "LatticeAuditProtocol",
    "AuditDecision",
    
    # Persistence
    "AuditStore",
    "AuditRecord",
    "SQLiteAuditStore",
    
    # Escrow
    "EscrowEntry",
    
    # External review
    "ExternalReviewRequest",
    "ExternalReviewResponse",
    
    # Core functions
    "compute_irreversibility_score",
    "infer_tier",
    "infer_tier_with_jitter",
    
    # Logging
    "logger",
]
