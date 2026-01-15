#!/usr/bin/env python3
"""
Lattice Audit Protocol - Command Line Interface

Usage:
    lap evaluate <evidence.json>   Evaluate an action from JSON evidence file
    lap verify                     Verify hash chain integrity
    lap status                     Show escrow queue status
    lap history [--limit N]        Show recent audit history
    lap demo                       Run the demo
    lap config                     Show current configuration
    lap schema-validate <path>      Validate a LAP artifact or audit pack against JSON Schemas
                                  (path may be a .json file, an audit-pack directory, or a .zip)
    lap anchor <pack> --out <file>  Compute transparency anchors for an audit pack (dir or .zip)
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional, Tuple, List

from lattice_audit_v1_7 import (
    LatticeAuditProtocol,
    SQLiteAuditStore,
    EvidenceObject,
    IrreversibilityAssessment,
    IrreversibilityFactors,
    UncertaintyBand,
    AlternativeOption,
    PMIPolicy,
    EscrowPolicy,
    IrreversibilityScoringPolicy,
    AuditOutcome,
    logger as lap_logger,
)



def setup_logging(verbose: bool = False):
    """Configure logging for CLI usage."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    )
    lap_logger.setLevel(level)


def load_config(config_path: Optional[Path]) -> dict:
    """
    Load configuration from JSON file.
    
    HARDENING (v1.8.0): Added JSON decode error handling.
    On invalid JSON, raises clear error rather than silent failure.
    """
    if config_path and config_path.exists():
        try:
            with open(config_path) as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"CONFIG_ERROR: Invalid JSON in config file '{config_path}': {e}. "
                f"Please check the config file syntax."
            ) from e
        except Exception as e:
            raise ValueError(
                f"CONFIG_ERROR: Failed to read config file '{config_path}': {e}"
            ) from e
    return {}


def create_protocol_from_config(config: dict, db_path: str = "lattice_audit.db") -> LatticeAuditProtocol:
    """Create a LatticeAuditProtocol instance from config dict.
    
    NOTE: strict_persistence defaults to True for "fail-dead" safety.
    All T3 God-Lock safeguards are loaded from config.
    """
    pmi_config = config.get("pmi_policy", {})
    pmi_policy = PMIPolicy(
        # Basic thresholds
        necessity_threshold_t2=pmi_config.get("necessity_threshold_t2", 0.80),
        necessity_threshold_t3=pmi_config.get("necessity_threshold_t3", 0.90),
        suffering_threshold_t2=pmi_config.get("suffering_threshold_t2", 0.35),
        suffering_threshold_t3=pmi_config.get("suffering_threshold_t3", 0.20),
        novelty_threshold_t2=pmi_config.get("novelty_threshold_t2", 0.60),
        novelty_threshold_t3=pmi_config.get("novelty_threshold_t3", 0.40),
        irreversibility_confidence_min=pmi_config.get("irreversibility_confidence_min", 0.50),
        reversible_preference_margin=pmi_config.get("reversible_preference_margin", 0.05),
        
        # T3 Exception Criteria
        t3_min_necessity=pmi_config.get("t3_min_necessity", 0.90),
        t3_max_suffering=pmi_config.get("t3_max_suffering", 0.20),
        t3_max_novelty_loss=pmi_config.get("t3_max_novelty_loss", 0.40),
        t3_min_confidence=pmi_config.get("t3_min_confidence", 0.85),
        t3_requires_external_review=pmi_config.get("t3_requires_external_review", True),
        t3_requires_no_strong_objections=pmi_config.get("t3_requires_no_strong_objections", True),
        t3_min_alternatives_evaluated=pmi_config.get("t3_min_alternatives_evaluated", 2),
        
        # God-Lock Structural Safeguards
        t3_max_approval_rate=pmi_config.get("t3_max_approval_rate", 0.10),
        t3_approval_rate_window=pmi_config.get("t3_approval_rate_window", 50),
        t3_cooling_period_seconds=pmi_config.get("t3_cooling_period_seconds", 3600),
        t3_escalation_threshold=pmi_config.get("t3_escalation_threshold", 3),
        t3_escalation_min_reviewers=pmi_config.get("t3_escalation_min_reviewers", 2),
        t3_requires_uncertainty_acknowledgment=pmi_config.get("t3_requires_uncertainty_acknowledgment", True),
        
        # Dynamic thresholds with T3 jitter immunity
        enable_threshold_jitter=pmi_config.get("enable_threshold_jitter", False),
        threshold_jitter_range=pmi_config.get("threshold_jitter_range", 0.05),
        t3_jitter_immune=pmi_config.get("t3_jitter_immune", True),
        t3_jitter_hardening=pmi_config.get("t3_jitter_hardening", 0.5),
    )
    
    escrow_config = config.get("escrow_policy", {})
    escrow_policy = EscrowPolicy(
        max_duration_seconds=escrow_config.get("max_duration_seconds", 7 * 24 * 3600),
        reevaluation_interval_seconds=escrow_config.get("reevaluation_interval_seconds", 24 * 3600),
    )
    
    irr_config = config.get("irreversibility_policy", {})
    irr_policy = IrreversibilityScoringPolicy(
        w_temporal=irr_config.get("w_temporal", 1.0),
        w_informational=irr_config.get("w_informational", 1.0),
        w_causal=irr_config.get("w_causal", 1.0),
        catastrophic_floor=irr_config.get("catastrophic_floor", 0.10),
        enforce_catastrophic_floor=irr_config.get("enforce_catastrophic_floor", True),
    )
    
    store = SQLiteAuditStore(db_path)
    
    # NOTE: strict_persistence defaults to TRUE for "fail-dead" safety
    # This ensures no audit logs are lost in a crash
    return LatticeAuditProtocol(
        pmi_policy=pmi_policy,
        escrow_policy=escrow_policy,
        irr_policy=irr_policy,
        store=store,
        strict_persistence=config.get("strict_persistence", True),  # Default TRUE for safety
    )


def parse_evidence_json(data: dict) -> EvidenceObject:
    """Parse evidence from JSON dict."""
    irr_data = data["irreversibility"]
    factors = IrreversibilityFactors(
        temporal_reversibility=irr_data["factors"]["temporal_reversibility"],
        informational_reversibility=irr_data["factors"]["informational_reversibility"],
        causal_reversibility=irr_data["factors"]["causal_reversibility"],
    )
    irreversibility = IrreversibilityAssessment(
        factors=factors,
        method=irr_data["method"],
        notes=irr_data.get("notes", ""),
        reversibility_plan=irr_data.get("reversibility_plan", ""),
        assessor=irr_data["assessor"],
        confidence=irr_data["confidence"],
    )
    
    outcome_data = data["outcome_delta"]
    outcome_delta = UncertaintyBand(
        lower=outcome_data["lower"],
        upper=outcome_data["upper"],
        confidence_level=outcome_data["confidence_level"],
    )
    
    alternatives = []
    for alt_data in data.get("alternatives", []):
        alt_irr = alt_data["irreversibility"]
        alt_factors = IrreversibilityFactors(
            temporal_reversibility=alt_irr["factors"]["temporal_reversibility"],
            informational_reversibility=alt_irr["factors"]["informational_reversibility"],
            causal_reversibility=alt_irr["factors"]["causal_reversibility"],
        )
        alt_irreversibility = IrreversibilityAssessment(
            factors=alt_factors,
            method=alt_irr["method"],
            notes=alt_irr.get("notes", ""),
            reversibility_plan=alt_irr.get("reversibility_plan", ""),
            assessor=alt_irr["assessor"],
            confidence=alt_irr["confidence"],
        )
        alt_outcome = UncertaintyBand(
            lower=alt_data["expected_utility"]["lower"],
            upper=alt_data["expected_utility"]["upper"],
            confidence_level=alt_data["expected_utility"]["confidence_level"],
        )
        alternatives.append(AlternativeOption(
            description=alt_data["description"],
            expected_utility=alt_outcome,
            irreversibility=alt_irreversibility,
            estimated_compute_cost=alt_data.get("estimated_compute_cost", 1.0),
            tags=alt_data.get("tags", []),
        ))
    
    return EvidenceObject(
        action_id=data["action_id"],
        description=data["description"],
        timestamp_utc=data["timestamp_utc"],
        irreversibility=irreversibility,
        outcome_delta=outcome_delta,
        necessity_confidence=data["necessity_confidence"],
        novelty_loss_estimate=data["novelty_loss_estimate"],
        novelty_method=data["novelty_method"],
        suffering_risk_estimate=data["suffering_risk_estimate"],
        suffering_method=data["suffering_method"],
        alternatives=alternatives,
        counterfactual_gap_statement=data.get("counterfactual_gap_statement", ""),
        provenance=data.get("provenance", {}),
    )


REQUIRED_EVIDENCE_FIELDS = [
    "action_id", "description", "timestamp_utc", "irreversibility",
    "outcome_delta", "necessity_confidence", "novelty_loss_estimate",
    "novelty_method", "suffering_risk_estimate", "suffering_method"
]

REQUIRED_IRREVERSIBILITY_FIELDS = ["factors", "method", "assessor", "confidence"]
REQUIRED_FACTOR_FIELDS = ["temporal_reversibility", "informational_reversibility", "causal_reversibility"]
REQUIRED_OUTCOME_FIELDS = ["lower", "upper", "confidence_level"]


def validate_evidence_json(data: dict) -> Tuple[bool, List[str]]:
    """
    Validate evidence JSON structure before parsing.
    
    Returns:
        (is_valid, errors): Tuple of validity and list of error messages
    """
    errors = []
    
    # Check top-level required fields
    for field in REQUIRED_EVIDENCE_FIELDS:
        if field not in data:
            errors.append(f"Missing required field: {field}")
    
    if errors:
        return (False, errors)
    
    # Validate irreversibility structure
    irr = data.get("irreversibility", {})
    for field in REQUIRED_IRREVERSIBILITY_FIELDS:
        if field not in irr:
            errors.append(f"Missing irreversibility.{field}")
    
    factors = irr.get("factors", {})
    for field in REQUIRED_FACTOR_FIELDS:
        if field not in factors:
            errors.append(f"Missing irreversibility.factors.{field}")
        elif not isinstance(factors.get(field), (int, float)):
            errors.append(f"irreversibility.factors.{field} must be a number")
        elif not 0 <= factors.get(field, -1) <= 1:
            errors.append(f"irreversibility.factors.{field} must be in [0, 1]")
    
    # Validate outcome_delta structure
    od = data.get("outcome_delta", {})
    for field in REQUIRED_OUTCOME_FIELDS:
        if field not in od:
            errors.append(f"Missing outcome_delta.{field}")
    
    # Validate numeric ranges
    nec = data.get("necessity_confidence")
    if nec is not None and not (0 <= nec <= 1):
        errors.append(f"necessity_confidence must be in [0, 1], got {nec}")
    
    nov = data.get("novelty_loss_estimate")
    if nov is not None and not (0 <= nov <= 1):
        errors.append(f"novelty_loss_estimate must be in [0, 1], got {nov}")
    
    suf = data.get("suffering_risk_estimate")
    if suf is not None and not (0 <= suf <= 1):
        errors.append(f"suffering_risk_estimate must be in [0, 1], got {suf}")
    
    # Validate alternatives if present
    for i, alt in enumerate(data.get("alternatives", [])):
        if "description" not in alt:
            errors.append(f"alternatives[{i}]: missing description")
        if "expected_utility" not in alt:
            errors.append(f"alternatives[{i}]: missing expected_utility")
        if "irreversibility" not in alt:
            errors.append(f"alternatives[{i}]: missing irreversibility")
    
    return (len(errors) == 0, errors)


def cmd_evaluate(args):
    """Evaluate an action from evidence JSON file."""
    config = load_config(args.config)
    proto = create_protocol_from_config(config, args.db)
    
    # Load and validate JSON
    try:
        with open(args.evidence_file) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in {args.evidence_file}: {e}", file=sys.stderr)
        sys.exit(3)
    except FileNotFoundError:
        print(f"ERROR: File not found: {args.evidence_file}", file=sys.stderr)
        sys.exit(3)
    
    # Validate structure before parsing
    valid, validation_errors = validate_evidence_json(data)
    if not valid:
        print(f"\nERROR: Evidence validation failed:", file=sys.stderr)
        for err in validation_errors:
            print(f"  - {err}", file=sys.stderr)
        print(f"\nSee evidence.example.json for correct structure.", file=sys.stderr)
        sys.exit(3)
    
    try:
        evidence = parse_evidence_json(data)
    except KeyError as e:
        print(f"ERROR: Missing required field in evidence: {e}", file=sys.stderr)
        sys.exit(3)
    except Exception as e:
        print(f"ERROR: Failed to parse evidence: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(3)
    
    decision = proto.evaluate_action(evidence)
    
    print(f"\n{'='*60}")
    print(f"DECISION: {decision.outcome.value.upper()}")
    print(f"{'='*60}")
    print(f"Action ID:     {evidence.action_id}")
    print(f"Tier:          {decision.tier.name}")
    print(f"Irreversibility: {decision.irreversibility_score:.3f}")
    print(f"Reason:        {decision.reason}")
    
    if decision.auditor_outputs:
        print(f"\nAuditor Outputs:")
        for ao in decision.auditor_outputs:
            status = "OBJECTION" if ao.objection else (ao.recommendation.value if ao.recommendation else "OK")
            print(f"  - {ao.role.value}: {status} (conf={ao.confidence:.2f})")
    
    print(f"{'='*60}\n")
    
    # Exit code based on outcome
    if decision.outcome == AuditOutcome.APPROVE:
        sys.exit(0)
    elif decision.outcome == AuditOutcome.DENY:
        sys.exit(1)
    else:  # ESCROW or REQUIRE_EXTERNAL_REVIEW
        sys.exit(2)


def cmd_verify(args):
    """Verify hash chain integrity."""
    store = SQLiteAuditStore(args.db)
    
    print(f"Verifying hash chain in {args.db}...")
    print(f"Total records: {store.count()}")
    
    # Basic chain verification
    valid, errors = store.verify_chain()
    if valid:
        print("✓ Chain structure: OK")
    else:
        print("✗ Chain structure: ERRORS FOUND")
        for err in errors:
            print(f"  - {err}")
    
    # Full recomputation
    if args.deep:
        print("\nPerforming deep verification (recomputing all hashes)...")
        valid2, errors2 = store.recompute_and_verify()
        if valid2:
            print("✓ Hash recomputation: OK")
        else:
            print("✗ Hash recomputation: ERRORS FOUND")
            for err in errors2:
                print(f"  - {err}")
    
    if valid and (not args.deep or valid2):
        print("\n✓ Audit log integrity verified")
        sys.exit(0)
    else:
        print("\n✗ Audit log integrity check FAILED")
        sys.exit(1)


def cmd_status(args):
    """Show escrow queue status."""
    config = load_config(args.config)
    proto = create_protocol_from_config(config, args.db)
    
    # First, run reevaluation to handle any expirations
    results = proto.reevaluate_escrow()
    
    escrowed = proto.list_escrowed_actions()
    
    print(f"\n{'='*60}")
    print(f"ESCROW QUEUE STATUS")
    print(f"{'='*60}")
    print(f"Database: {args.db}")
    print(f"Pending actions: {len(escrowed)}")
    
    if results:
        print(f"\nRecent reevaluation results:")
        for action_id, outcome, reason in results:
            print(f"  - {action_id}: {outcome.value} - {reason}")
    
    if escrowed:
        print(f"\nPending escrow entries:")
        for action_id, entry in escrowed:
            print(f"\n  {action_id}:")
            print(f"    Status:    {entry.status}")
            print(f"    Created:   {entry.created_at_utc}")
            print(f"    Expires:   {entry.expires_at_utc}")
            print(f"    Next eval: {entry.next_reeval_at_utc}")
            print(f"    Reason:    {entry.reason[:60]}...")
    
    print(f"{'='*60}\n")


def cmd_history(args):
    """Show recent audit history."""
    store = SQLiteAuditStore(args.db)
    
    records = store.get_recent(limit=args.limit)
    
    print(f"\n{'='*60}")
    print(f"AUDIT HISTORY (last {len(records)} records)")
    print(f"{'='*60}")
    
    for rec in reversed(records):  # Show oldest first
        print(f"\n{rec.timestamp_utc} | {rec.action_id}")
        print(f"  Tier: {rec.tier}, Outcome: {rec.outcome}")
        print(f"  Reason: {rec.reason[:70]}...")
        print(f"  Hash: {rec.record_hash[:16]}...")
    
    print(f"\n{'='*60}")
    print(f"Total records in database: {store.count()}")
    print(f"{'='*60}\n")


def cmd_demo(args):
    """Run the demo."""
    from lattice_audit_v1_7 import demo
    demo()


def cmd_config(args):
    """Show current configuration."""
    config = load_config(args.config)
    
    print(f"\n{'='*60}")
    print(f"CONFIGURATION")
    print(f"{'='*60}")
    print(f"Config file: {args.config or '(using defaults)'}")
    print(f"Database: {args.db}")
    
    proto = create_protocol_from_config(config, args.db)
    
    print(f"\nPMI Policy:")
    print(f"  necessity_threshold_t2: {proto.pmi_policy.necessity_threshold_t2}")
    print(f"  necessity_threshold_t3: {proto.pmi_policy.necessity_threshold_t3}")
    print(f"  suffering_threshold_t2: {proto.pmi_policy.suffering_threshold_t2}")
    print(f"  suffering_threshold_t3: {proto.pmi_policy.suffering_threshold_t3}")
    print(f"  novelty_threshold_t2: {proto.pmi_policy.novelty_threshold_t2}")
    print(f"  novelty_threshold_t3: {proto.pmi_policy.novelty_threshold_t3}")
    
    print(f"\nT3 God-Lock Safeguards:")
    print(f"  t3_max_approval_rate: {proto.pmi_policy.t3_max_approval_rate}")
    print(f"  t3_cooling_period_seconds: {proto.pmi_policy.t3_cooling_period_seconds}")
    print(f"  t3_escalation_threshold: {proto.pmi_policy.t3_escalation_threshold}")
    print(f"  t3_requires_uncertainty_acknowledgment: {proto.pmi_policy.t3_requires_uncertainty_acknowledgment}")
    
    print(f"\nEscrow Policy:")
    print(f"  max_duration: {proto.escrow_policy.max_duration_seconds / 3600:.1f} hours")
    print(f"  reevaluation_interval: {proto.escrow_policy.reevaluation_interval_seconds / 3600:.1f} hours")
    print(f"  default_on_expiry: {proto.escrow_policy.default_on_expiry.value}")
    
    print(f"\nIrreversibility Scoring:")
    print(f"  w_temporal: {proto.irr_policy.w_temporal}")
    print(f"  w_informational: {proto.irr_policy.w_informational}")
    print(f"  w_causal: {proto.irr_policy.w_causal}")
    
    print(f"{'='*60}\n")


def cmd_stress_test(args):
    """
    Run stress test with jittered thresholds.
    
    This tests decision stability under threshold drift by evaluating the same
    evidence multiple times with randomized tier boundaries. If decisions flip
    frequently, the evidence is near a boundary and may be sensitive to drift.
    """
    from lattice_audit_v1_7 import (
        TierBoundaries, infer_tier_with_jitter, compute_irreversibility_score,
        IrreversibilityScoringPolicy
    )
    
    config = load_config(args.config)
    
    # Load evidence
    try:
        with open(args.evidence_file) as f:
            data = json.load(f)
    except Exception as e:
        print(f"ERROR: Failed to load evidence: {e}", file=sys.stderr)
        sys.exit(3)
    
    valid, errors = validate_evidence_json(data)
    if not valid:
        print(f"ERROR: Invalid evidence: {errors}", file=sys.stderr)
        sys.exit(3)
    
    evidence = parse_evidence_json(data)
    
    # Compute base scores
    irr_policy = IrreversibilityScoringPolicy()
    irr = compute_irreversibility_score(evidence.irreversibility, irr_policy)
    
    print(f"\n{'='*60}")
    print(f"STRESS TEST: Threshold Jitter Stability Analysis")
    print(f"{'='*60}")
    print(f"Action ID: {evidence.action_id}")
    print(f"Irreversibility Score: {irr:.4f}")
    print(f"Suffering Risk: {evidence.suffering_risk_estimate:.4f}")
    print(f"Iterations: {args.iterations}")
    print(f"Jitter Range: ±{args.jitter*100:.1f}%")
    print(f"{'='*60}\n")
    
    # Run jitter tests
    tier_counts = {}
    tier_sequence = []  # Track sequence for variance analysis
    base_tier, _ = infer_tier_with_jitter(irr, evidence.suffering_risk_estimate, jitter_range=0.0)
    
    for i in range(args.iterations):
        tier, _ = infer_tier_with_jitter(irr, evidence.suffering_risk_estimate, jitter_range=args.jitter)
        tier_counts[tier.name] = tier_counts.get(tier.name, 0) + 1
        tier_sequence.append(tier.name)
    
    print("Tier Distribution:")
    for tier_name, count in sorted(tier_counts.items()):
        pct = count / args.iterations * 100
        bar = "█" * int(pct / 2)
        match_marker = " ← BASE" if tier_name == base_tier.name else ""
        print(f"  {tier_name:20s}: {count:4d} ({pct:5.1f}%) {bar}{match_marker}")
    
    # Compute stability metrics
    dominant_tier = max(tier_counts, key=tier_counts.get)
    dominant_pct = tier_counts[dominant_tier] / args.iterations * 100
    unique_tiers = len(tier_counts)
    
    # Count tier transitions (indicates boundary proximity)
    transitions = sum(1 for i in range(1, len(tier_sequence)) if tier_sequence[i] != tier_sequence[i-1])
    transition_rate = transitions / (args.iterations - 1) * 100
    
    # Stability Score: 100 = perfectly stable, 0 = chaotic
    stability_score = dominant_pct * (1.0 - transition_rate / 100) ** 0.5
    
    # Check if any T3 results appeared
    t3_count = tier_counts.get("T3_CATASTROPHIC", 0)
    t3_pct = t3_count / args.iterations * 100
    
    print(f"\n{'='*60}")
    print(f"STABILITY METRICS")
    print(f"{'='*60}")
    print(f"  Stability Score:     {stability_score:.1f}/100")
    print(f"  Dominant Tier:       {dominant_tier} ({dominant_pct:.1f}%)")
    print(f"  Unique Tiers:        {unique_tiers}")
    print(f"  Transition Rate:     {transition_rate:.1f}%")
    print(f"  T3 Occurrences:      {t3_count} ({t3_pct:.1f}%)")
    
    print(f"\nSTABILITY CLASSIFICATION:")
    
    # Structural instability flag: if outcome EVER changes, flag it
    is_structurally_unstable = unique_tiers > 1
    
    if stability_score >= 95:
        print(f"  ✓ STABLE: Score {stability_score:.1f} - decision is robust to threshold drift")
    elif stability_score >= 80:
        print(f"  ⚠ MARGINAL: Score {stability_score:.1f} - action is near a tier boundary")
        print(f"    RECOMMENDATION: Conservative tier escalation advised")
    else:
        print(f"  ✗ UNSTABLE: Score {stability_score:.1f} - action straddles tier boundaries")
        print(f"    RECOMMENDATION: Treat as highest observed tier ({max(tier_counts.keys())})")
    
    # Special warning if T3 ever appeared
    if t3_count > 0 and base_tier.name != "T3_CATASTROPHIC":
        print(f"\n  ⚠ T3 WARNING: {t3_pct:.1f}% of jitter runs classified as CATASTROPHIC")
        print(f"    Despite base tier being {base_tier.name}, this action should be")
        print(f"    treated as potentially catastrophic due to boundary proximity.")
    
    # Structural instability warning
    if is_structurally_unstable:
        print(f"\n  ⚠ STRUCTURAL INSTABILITY DETECTED")
        print(f"    Outcome changed {transitions} times across {args.iterations} iterations.")
        print(f"    This action's classification is sensitive to measurement noise.")
    
    # Check if base tier matches dominant
    if base_tier.name != dominant_tier:
        print(f"\n  ⚠ TIER MISMATCH: Base tier ({base_tier.name}) differs from dominant ({dominant_tier})")
    
    print(f"\n{'='*60}\n")
    
    # Exit code based on stability
    # 0 = stable, 1 = marginal, 2 = unstable, 3 = T3 appeared unexpectedly
    if t3_count > 0 and base_tier.name != "T3_CATASTROPHIC":
        sys.exit(3)  # T3 warning
    elif stability_score >= 95:
        sys.exit(0)
    elif stability_score >= 80:
        sys.exit(1)
    else:
        sys.exit(2)


def cmd_diagnostics(args):
    """
    Run comprehensive governance diagnostics.
    
    Checks for:
    - Auditor independence/correlation
    - Decision entropy (approval bias)
    - Auditor collusion indicators
    - Per-agent rate limits
    """
    config = load_config(args.config)
    proto = create_protocol_from_config(config, args.db)
    
    print(f"\n{'='*60}")
    print(f"GOVERNANCE DIAGNOSTICS")
    print(f"{'='*60}")
    
    # Basic diagnostics
    diag = proto.get_governance_diagnostics()
    
    print(f"\nTimestamp: {diag['timestamp']}")
    print(f"Escrow Queue Size: {diag['escrow_queue_size']}")
    
    # Auditor Independence
    print(f"\n--- AUDITOR INDEPENDENCE ---")
    nmi = diag.get('auditor_independence', {})
    if nmi.get('status') == 'computed':
        print(f"  Auditors Analyzed: {nmi.get('auditor_count')}")
        print(f"  Independence Concern: {'YES ⚠' if nmi.get('independence_concern') else 'No'}")
        if nmi.get('high_correlation_pairs'):
            print(f"  High Correlation Pairs: {nmi.get('high_correlation_pairs')}")
    else:
        print(f"  Status: {nmi.get('status', 'unknown')}")
    
    # Decision Entropy
    print(f"\n--- DECISION ENTROPY ---")
    entropy = diag.get('decision_entropy', {})
    if entropy.get('status') == 'computed':
        print(f"  Records Analyzed: {entropy.get('records_analyzed')}")
        print(f"  Entropy: {entropy.get('entropy', 0):.3f} (max: {entropy.get('max_entropy', 0):.3f})")
        print(f"  Normalized: {entropy.get('normalized_entropy', 0):.1%}")
        print(f"  Approval Rate: {entropy.get('approval_rate', 0):.1%}")
        print(f"  Approval Bias Warning: {'YES ⚠' if entropy.get('approval_bias_warning') else 'No'}")
        print(f"  Low Entropy Warning: {'YES ⚠' if entropy.get('low_entropy_warning') else 'No'}")
    else:
        print(f"  Status: {entropy.get('status', 'unknown')}")
    
    # Collusion Check
    print(f"\n--- COLLUSION DETECTION ---")
    collusion = diag.get('collusion_check', {})
    if collusion.get('status') == 'computed':
        print(f"  Auditors Analyzed: {collusion.get('auditors_analyzed')}")
        print(f"  Collusion Suspected: {'YES ⚠' if collusion.get('collusion_suspected') else 'No'}")
        if collusion.get('evidence'):
            for ev in collusion.get('evidence', []):
                print(f"    - {ev}")
    else:
        print(f"  Status: {collusion.get('status', 'unknown')}")
    
    # Per-Agent Stats
    if args.agents:
        print(f"\n--- PER-AGENT RATE LIMITS ---")
        agent_stats = proto.get_per_agent_rate_limits(window=args.window)
        if isinstance(agent_stats, dict) and agent_stats.get('status') != 'agent_history_not_available':
            for agent_id, stats in agent_stats.items():
                if stats.get('status') != 'computed':
                    continue
                print(f"\n  Agent: {agent_id}")
                print(f"    Total Actions: {stats.get('total_actions')}")
                print(f"    Approval Rate: {stats.get('approval_rate', 0):.1%}")
                print(f"    T3 Rate: {stats.get('t3_rate', 0):.1%}")
                if stats.get('high_approval_rate_warning'):
                    print(f"    ⚠ HIGH APPROVAL RATE WARNING")
                if stats.get('necessity_inflation_warning'):
                    print(f"    ⚠ NECESSITY INFLATION WARNING (trend: +{stats.get('necessity_trend', 0):.2f})")
    
    # Warnings Summary
    if diag.get('warnings'):
        print(f"\n{'='*60}")
        print(f"⚠ WARNINGS ({len(diag['warnings'])})")
        print(f"{'='*60}")
        for w in diag['warnings']:
            print(f"  • {w}")
    else:
        print(f"\n✓ No governance warnings detected")
    
    print(f"\n{'='*60}\n")


def cmd_export(args):
    """
    Export audit trail for external verification.
    
    Outputs a JSON file with hash-chained records suitable for
    independent verification by external systems.
    """
    config = load_config(args.config)
    proto = create_protocol_from_config(config, args.db)
    
    export = proto.export_audit_trail(
        start_time=args.start,
        end_time=args.end,
        format="json"
    )
    
    # Write to file or stdout
    output_json = json.dumps(export, indent=2)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_json)
        print(f"Exported {export['record_count']} records to {args.output}")
        print(f"Chain Integrity: {'✓ VALID' if export['chain_integrity'] else '✗ INVALID'}")
        print(f"Export Hash: {export['export_hash'][:16]}...")
    else:
        print(output_json)


def cmd_schema_validate(args):
    """Validate a LAP artifact or audit pack against the published JSON Schemas."""

    from lap_schema_validate import validate_path, list_schemas

    if args.list_schemas:
        for name in list_schemas():
            print(name)
        return

    ok, msgs = validate_path(
        Path(args.path),
        schema_name=args.schema,
        schemas_dir=Path(args.schemas_dir) if args.schemas_dir else None,
        strict=args.strict,
    )

    for m in msgs:
        mark = "✓" if m.ok else "✗"
        print(f"{mark} {m.code}: {m.detail}")

    if not ok:
        raise SystemExit(2)


def cmd_anchor(args):
    """Compute transparency anchor entries for an audit pack (dir or .zip)."""

    from lap_gateway.transparency import (
        FileTransparencyLogger,
        HttpTransparencyLogger,
        compute_anchor_entries_for_audit_pack_dir,
        compute_anchor_entries_for_audit_pack_zip,
    )

    in_path = Path(args.pack)
    out_path = Path(args.out)

    if not in_path.exists():
        raise SystemExit(f"Input not found: {in_path}")

    include_receipts = not args.no_receipts
    include_dsse = not args.no_dsse

    if in_path.is_dir():
        entries = compute_anchor_entries_for_audit_pack_dir(
            in_path,
            include_receipts=include_receipts,
            include_dsse=include_dsse,
        )
    elif in_path.suffix.lower() == ".zip":
        entries = compute_anchor_entries_for_audit_pack_zip(
            in_path,
            include_receipts=include_receipts,
            include_dsse=include_dsse,
            include_auditpack_zip_hash=args.include_auditpack,
        )
    else:
        raise SystemExit("lap anchor expects an audit-pack directory or a .zip")

    if not entries and args.fail_on_empty:
        raise SystemExit("No anchors produced (missing receipts/dsse?)")

    logger = FileTransparencyLogger(out_path)
    # Overwrite unless --append
    if not args.append and out_path.exists():
        out_path.write_text("", encoding="utf-8")
    for e in entries:
        logger.append(e)

    print(f"Wrote {len(entries)} anchor entries to {out_path}")

    # Optional HTTP push (PR-016)
    if getattr(args, "push", None):
        required = bool(getattr(args, "required", False)) or (
            os.environ.get("ANCHOR_REQUIRED", "").lower() in ("1", "true", "yes", "on")
        )
        http_logger = HttpTransparencyLogger(args.push, required=required)
        pushed = 0
        for e in entries:
            try:
                ok = http_logger.append(e)
            except Exception as ex:
                # Avoid stack traces in CLI; fail closed if required.
                if required:
                    print(f"ERROR: transparency push failed: {ex}", file=sys.stderr)
                    raise SystemExit(2)
                print(f"WARNING: transparency push failed: {ex}", file=sys.stderr)
                ok = False
            if ok:
                pushed += 1
        print(f"Pushed {pushed}/{len(entries)} anchor entries to {args.push} (required={required})")


def main():
    parser = argparse.ArgumentParser(
        description="Lattice Audit Protocol CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--db", default="lattice_audit.db", help="Path to audit database")
    parser.add_argument("--config", type=Path, help="Path to config JSON file")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # evaluate command
    eval_parser = subparsers.add_parser("evaluate", help="Evaluate an action")
    eval_parser.add_argument("evidence_file", help="Path to evidence JSON file")
    eval_parser.set_defaults(func=cmd_evaluate)
    
    # verify command
    verify_parser = subparsers.add_parser("verify", help="Verify hash chain integrity")
    verify_parser.add_argument("--deep", action="store_true", help="Recompute all hashes")
    verify_parser.set_defaults(func=cmd_verify)
    
    # status command
    status_parser = subparsers.add_parser("status", help="Show escrow queue status")
    status_parser.set_defaults(func=cmd_status)
    
    # history command
    history_parser = subparsers.add_parser("history", help="Show audit history")
    history_parser.add_argument("--limit", type=int, default=20, help="Number of records")
    history_parser.set_defaults(func=cmd_history)
    
    # demo command
    demo_parser = subparsers.add_parser("demo", help="Run demo")
    demo_parser.set_defaults(func=cmd_demo)
    
    # config command
    config_parser = subparsers.add_parser("config", help="Show configuration")
    config_parser.set_defaults(func=cmd_config)
    
    # stress-test command
    stress_parser = subparsers.add_parser("stress-test", help="Run threshold jitter stability test")
    stress_parser.add_argument("evidence_file", help="Path to evidence JSON file")
    stress_parser.add_argument("--iterations", type=int, default=100, help="Number of jitter iterations")
    stress_parser.add_argument("--jitter", type=float, default=0.05, help="Jitter range (0.05 = ±5%%)")
    stress_parser.set_defaults(func=cmd_stress_test)
    
    # diagnostics command
    diag_parser = subparsers.add_parser("diagnostics", help="Run governance diagnostics")
    diag_parser.add_argument("--window", type=int, default=100, help="Analysis window size")
    diag_parser.add_argument("--agents", action="store_true", help="Include per-agent analysis")
    diag_parser.set_defaults(func=cmd_diagnostics)
    
    # export command
    export_parser = subparsers.add_parser("export", help="Export audit trail for external verification")
    export_parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    export_parser.add_argument("--start", help="Start timestamp (ISO format)")
    export_parser.add_argument("--end", help="End timestamp (ISO format)")
    export_parser.set_defaults(func=cmd_export)

    # anchor command (PR-006)
    anchor_parser = subparsers.add_parser("anchor", help="Compute transparency anchors for an audit pack")
    anchor_parser.add_argument("pack", help="Path to audit-pack directory or .zip")
    anchor_parser.add_argument("--out", required=True, help="Output JSONL path (anchors.jsonl)")
    anchor_parser.add_argument("--no-receipts", action="store_true", help="Do not include receipt anchors")
    anchor_parser.add_argument("--no-dsse", action="store_true", help="Do not include DSSE envelope anchors")
    anchor_parser.add_argument("--include-auditpack", action="store_true", help="Include a hash of the pack .zip bytes")
    anchor_parser.add_argument("--append", action="store_true", help="Append to output file (default overwrites)")
    anchor_parser.add_argument("--fail-on-empty", action="store_true", help="Fail if no anchors are produced")
    anchor_parser.add_argument("--mode", default="hash-only", choices=["hash-only", "metadata"], help="Privacy mode for anchors (default: hash-only)")
    anchor_parser.add_argument("--gateway-id", help="Optional gateway identifier to include in metadata mode")
    anchor_parser.add_argument("--push", help="Optional URL to POST anchors to (HTTP backend)")
    anchor_parser.add_argument("--required", action="store_true", help="Fail if push to --push fails (or set ANCHOR_REQUIRED=true)")
    anchor_parser.set_defaults(func=cmd_anchor)

    # schema-validate command
    sv_parser = subparsers.add_parser(
        "schema-validate",
        help="Validate LAP artifacts or audit packs against JSON Schemas",
    )
    sv_parser.add_argument(
        "path",
        help="Path to a .json artifact, an audit-pack directory, or an audit-pack .zip",
    )
    sv_parser.add_argument(
        "--schema",
        default=None,
        help="Schema name override (evidence|decision|token|receipt|external_approval|audit_pack_manifest)",
    )
    sv_parser.add_argument(
        "--schemas-dir",
        default=None,
        help="Directory containing schema files (default: spec/schemas)",
    )
    sv_parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat missing optional files in an audit pack as errors",
    )
    sv_parser.add_argument(
        "--list-schemas",
        action="store_true",
        help="List supported schema names",
    )
    sv_parser.set_defaults(func=cmd_schema_validate)
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        sys.exit(1)
    
    setup_logging(args.verbose)
    args.func(args)


if __name__ == "__main__":
    main()
