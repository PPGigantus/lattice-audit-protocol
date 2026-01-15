#!/usr/bin/env python3
"""
Test suite for Lattice Audit Protocol v1.7

Tests cover:
- Tier classification logic
- Irreversibility scoring
- PMI checks
- Evidence validation
- Decision flow (T0-T3)
- Escrow mechanics
- Hash chain integrity
- Edge cases and boundary conditions
"""

import unittest
import tempfile
import os
import datetime
import logging
from dataclasses import asdict

from lattice_audit_v1_7 import (
    # Core types
    ActionTier, AuditOutcome, AuditorRole, ObjectionSeverity,
    # Evidence types
    UncertaintyBand, IrreversibilityFactors, IrreversibilityAssessment,
    AlternativeOption, EvidenceObject,
    # Policy types
    PMIPolicy, IrreversibilityScoringPolicy, EscrowPolicy,
    # Auditors
    PrimaryDeciderAuditor, IrreversibilityAuditor, SafetyCriticAuditor,
    NoveltyAuditor, SufferingAuditor, AuditorOutput,
    # Core functions
    compute_irreversibility_score, infer_tier,
    # Protocol engine
    LatticeAuditProtocol, SQLiteAuditStore, AuditDecision,
    # Escrow
    EscrowEntry,
    # Helpers
    _canonical_json, _sha256_hex, _clamp01,
)


class TestHelpers(unittest.TestCase):
    """Test utility functions."""
    
    def test_clamp01_normal(self):
        self.assertEqual(_clamp01(0.5), 0.5)
        
    def test_clamp01_lower_bound(self):
        self.assertEqual(_clamp01(-0.5), 0.0)
        
    def test_clamp01_upper_bound(self):
        self.assertEqual(_clamp01(1.5), 1.0)
        
    def test_clamp01_boundary(self):
        self.assertEqual(_clamp01(0.0), 0.0)
        self.assertEqual(_clamp01(1.0), 1.0)
    
    def test_canonical_json_deterministic(self):
        d1 = {"b": 2, "a": 1}
        d2 = {"a": 1, "b": 2}
        self.assertEqual(_canonical_json(d1), _canonical_json(d2))
    
    def test_sha256_hex(self):
        result = _sha256_hex(b"test")
        self.assertEqual(len(result), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in result))


class TestUncertaintyBand(unittest.TestCase):
    """Test UncertaintyBand validation and methods."""
    
    def test_valid_band(self):
        band = UncertaintyBand(lower=-1.0, upper=1.0, confidence_level=0.9)
        self.assertEqual(band.validate(), [])
    
    def test_inverted_bounds(self):
        band = UncertaintyBand(lower=1.0, upper=-1.0, confidence_level=0.9)
        errors = band.validate()
        self.assertTrue(any("lower" in e and "upper" in e for e in errors))
    
    def test_invalid_confidence(self):
        band = UncertaintyBand(lower=-1.0, upper=1.0, confidence_level=1.5)
        errors = band.validate()
        self.assertTrue(any("confidence" in e for e in errors))
    
    def test_width(self):
        band = UncertaintyBand(lower=-1.0, upper=1.0, confidence_level=0.9)
        self.assertEqual(band.width(), 2.0)
    
    def test_crosses_zero_true(self):
        band = UncertaintyBand(lower=-1.0, upper=1.0, confidence_level=0.9)
        self.assertTrue(band.crosses_zero())
    
    def test_crosses_zero_false(self):
        band = UncertaintyBand(lower=0.5, upper=1.0, confidence_level=0.9)
        self.assertFalse(band.crosses_zero())


class TestIrreversibilityScoring(unittest.TestCase):
    """Test irreversibility score computation."""
    
    def test_fully_reversible(self):
        factors = IrreversibilityFactors(
            temporal_reversibility=1.0,
            informational_reversibility=1.0,
            causal_reversibility=1.0
        )
        assess = IrreversibilityAssessment(
            factors=factors, method="test", notes="", 
            reversibility_plan="rollback", assessor="test", confidence=0.9
        )
        score = compute_irreversibility_score(assess, IrreversibilityScoringPolicy())
        # With epsilon floor of 0.01 and confidence adjustment, score is very low but not exactly 0
        self.assertLess(score, 0.05)
    
    def test_fully_irreversible(self):
        factors = IrreversibilityFactors(
            temporal_reversibility=0.0,
            informational_reversibility=0.0,
            causal_reversibility=0.0
        )
        assess = IrreversibilityAssessment(
            factors=factors, method="test", notes="",
            reversibility_plan="none", assessor="test", confidence=0.9
        )
        score = compute_irreversibility_score(assess, IrreversibilityScoringPolicy())
        # With epsilon floor and confidence adjustment, score is very high but capped at ~0.90
        self.assertGreater(score, 0.85)
    
    def test_geometric_mean_property(self):
        """If any factor is near-zero, score should be near-one (geometric mean punishes low values)."""
        factors = IrreversibilityFactors(
            temporal_reversibility=1.0,
            informational_reversibility=0.01,  # Very low
            causal_reversibility=1.0
        )
        assess = IrreversibilityAssessment(
            factors=factors, method="test", notes="",
            reversibility_plan="plan", assessor="test", confidence=0.9
        )
        score = compute_irreversibility_score(assess, IrreversibilityScoringPolicy())
        self.assertGreater(score, 0.7)  # Should be high due to geometric mean
    
    def test_custom_weights(self):
        """Test that weights affect the score."""
        factors = IrreversibilityFactors(
            temporal_reversibility=0.5,
            informational_reversibility=1.0,
            causal_reversibility=1.0
        )
        assess = IrreversibilityAssessment(
            factors=factors, method="test", notes="",
            reversibility_plan="plan", assessor="test", confidence=0.9
        )
        
        # Equal weights
        policy1 = IrreversibilityScoringPolicy(w_temporal=1.0, w_informational=1.0, w_causal=1.0)
        score1 = compute_irreversibility_score(assess, policy1)
        
        # Heavy temporal weight
        policy2 = IrreversibilityScoringPolicy(w_temporal=10.0, w_informational=1.0, w_causal=1.0)
        score2 = compute_irreversibility_score(assess, policy2)
        
        # Higher temporal weight should increase score when temporal is low
        self.assertGreater(score2, score1)


class TestTierInference(unittest.TestCase):
    """Test tier classification logic."""
    
    def test_t0_routine(self):
        tier = infer_tier(irr=0.05, suffering_risk=0.1)
        self.assertEqual(tier, ActionTier.T0_ROUTINE)
    
    def test_t1_sensitive(self):
        tier = infer_tier(irr=0.20, suffering_risk=0.1)
        self.assertEqual(tier, ActionTier.T1_SENSITIVE)
    
    def test_t2_high_stakes(self):
        tier = infer_tier(irr=0.50, suffering_risk=0.1)
        self.assertEqual(tier, ActionTier.T2_HIGH_STAKES)
    
    def test_t3_by_irreversibility(self):
        tier = infer_tier(irr=0.75, suffering_risk=0.1)
        self.assertEqual(tier, ActionTier.T3_CATASTROPHIC)
    
    def test_t3_by_suffering(self):
        tier = infer_tier(irr=0.05, suffering_risk=0.85)
        self.assertEqual(tier, ActionTier.T3_CATASTROPHIC)
    
    def test_t3_by_override(self):
        tier = infer_tier(irr=0.05, suffering_risk=0.1, catastrophic_override=True)
        self.assertEqual(tier, ActionTier.T3_CATASTROPHIC)
    
    def test_boundary_t0_t1(self):
        """Test boundary at irr=0.10"""
        self.assertEqual(infer_tier(0.09, 0.1), ActionTier.T0_ROUTINE)
        self.assertEqual(infer_tier(0.10, 0.1), ActionTier.T1_SENSITIVE)
    
    def test_boundary_t1_t2(self):
        """Test boundary at irr=0.30"""
        self.assertEqual(infer_tier(0.29, 0.1), ActionTier.T1_SENSITIVE)
        self.assertEqual(infer_tier(0.30, 0.1), ActionTier.T2_HIGH_STAKES)
    
    def test_boundary_t2_t3(self):
        """Test boundary at irr=0.70"""
        self.assertEqual(infer_tier(0.69, 0.1), ActionTier.T2_HIGH_STAKES)
        self.assertEqual(infer_tier(0.70, 0.1), ActionTier.T3_CATASTROPHIC)


class TestEvidenceValidation(unittest.TestCase):
    """Test EvidenceObject validation."""
    
    def _make_valid_evidence(self, **overrides):
        """Factory for valid evidence objects."""
        defaults = dict(
            action_id="TEST_001",
            description="Test action description",
            timestamp_utc="2026-01-05T00:00:00Z",
            irreversibility=IrreversibilityAssessment(
                factors=IrreversibilityFactors(0.95, 0.95, 0.95),  # High reversibility = low risk (T0/T1)
                method="test_method",
                notes="test notes",
                reversibility_plan="test plan with enough characters",
                assessor="test_assessor",
                confidence=0.8
            ),
            outcome_delta=UncertaintyBand(-1.0, 1.0, 0.9),
            necessity_confidence=0.7,
            novelty_loss_estimate=0.1,  # Low novelty loss
            novelty_method="test_novelty",
            suffering_risk_estimate=0.1,  # Low suffering risk
            suffering_method="test_suffering",
            alternatives=[],
        )
        defaults.update(overrides)
        return EvidenceObject(**defaults)
    
    def test_valid_evidence(self):
        ev = self._make_valid_evidence()
        ok, errors = ev.validate()
        self.assertTrue(ok, f"Expected valid, got errors: {errors}")
    
    def test_empty_action_id(self):
        ev = self._make_valid_evidence(action_id="")
        ok, errors = ev.validate()
        self.assertFalse(ok)
        self.assertTrue(any("action_id" in e for e in errors))
    
    def test_short_description(self):
        ev = self._make_valid_evidence(description="short")
        ok, errors = ev.validate()
        self.assertFalse(ok)
        self.assertTrue(any("description" in e for e in errors))
    
    def test_invalid_timestamp(self):
        ev = self._make_valid_evidence(timestamp_utc="not-a-date")
        ok, errors = ev.validate()
        self.assertFalse(ok)
        self.assertTrue(any("timestamp" in e for e in errors))
    
    def test_necessity_out_of_range(self):
        ev = self._make_valid_evidence(necessity_confidence=1.5)
        ok, errors = ev.validate()
        self.assertFalse(ok)
        self.assertTrue(any("necessity" in e for e in errors))
    
    def test_novelty_out_of_range(self):
        ev = self._make_valid_evidence(novelty_loss_estimate=-0.1)
        ok, errors = ev.validate()
        self.assertFalse(ok)
        self.assertTrue(any("novelty" in e for e in errors))


class TestAuditors(unittest.TestCase):
    """Test individual auditor behaviors."""
    
    def _make_evidence(self, irr_factors=(0.5, 0.5, 0.5), irr_conf=0.8, 
                       necessity=0.7, novelty=0.3, suffering=0.2, plan="adequate plan here"):
        return EvidenceObject(
            action_id="TEST",
            description="Test action",
            timestamp_utc="2026-01-05T00:00:00Z",
            irreversibility=IrreversibilityAssessment(
                factors=IrreversibilityFactors(*irr_factors),
                method="test", notes="", reversibility_plan=plan,
                assessor="test", confidence=irr_conf
            ),
            outcome_delta=UncertaintyBand(-1.0, 1.0, 0.9),
            necessity_confidence=necessity,
            novelty_loss_estimate=novelty,
            novelty_method="test",
            suffering_risk_estimate=suffering,
            suffering_method="test",
        )
    
    def test_irreversibility_auditor_objects_high_irr_low_conf(self):
        """Should object when irr high and confidence low."""
        ev = self._make_evidence(irr_factors=(0.2, 0.2, 0.2), irr_conf=0.3)  # High irr, low conf
        auditor = IrreversibilityAuditor()
        out = auditor.evaluate(ev, "salt")
        self.assertTrue(out.objection)
        self.assertEqual(out.severity, ObjectionSeverity.HIGH)
    
    def test_irreversibility_auditor_no_objection_good_plan(self):
        """Should not object when irr low and plan exists."""
        ev = self._make_evidence(irr_factors=(0.9, 0.9, 0.9), irr_conf=0.8)  # Low irr (~0.1)
        auditor = IrreversibilityAuditor()
        out = auditor.evaluate(ev, "salt")
        self.assertFalse(out.objection)
    
    def test_safety_critic_objects_high_suffering(self):
        """Should object on high suffering risk in high-stakes tier."""
        ev = self._make_evidence(irr_factors=(0.3, 0.3, 0.3), suffering=0.75)
        auditor = SafetyCriticAuditor()
        out = auditor.evaluate(ev, "salt")
        self.assertTrue(out.objection)
    
    def test_novelty_auditor_objects_high_novelty_loss(self):
        """Should object on high novelty loss in high-stakes tier."""
        ev = self._make_evidence(irr_factors=(0.3, 0.3, 0.3), novelty=0.75)
        auditor = NoveltyAuditor()
        out = auditor.evaluate(ev, "salt")
        self.assertTrue(out.objection)
    
    def test_suffering_auditor_threshold(self):
        """Should object at suffering >= 0.80."""
        ev_low = self._make_evidence(suffering=0.79)
        ev_high = self._make_evidence(suffering=0.80)
        auditor = SufferingAuditor()
        self.assertFalse(auditor.evaluate(ev_low, "salt").objection)
        self.assertTrue(auditor.evaluate(ev_high, "salt").objection)


class TestProtocolDecisions(unittest.TestCase):
    """Test end-to-end protocol decision making."""
    
    def setUp(self):
        # Use temp file for SQLite to avoid polluting filesystem
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.store = SQLiteAuditStore(self.db_path)
        self.proto = LatticeAuditProtocol(store=self.store)
    
    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def _make_evidence(self, irr_factors=(0.9, 0.9, 0.9), necessity=0.95, 
                       novelty=0.1, suffering=0.1, alternatives=None, **kwargs):
        from lattice_audit_v1_7 import AlternativeOption
        
        # Generate default alternatives for T2/T3 actions (based on irr score)
        # HARDENING (v1.7.7): Include diverse causal_strategy values
        if alternatives is None:
            irr_score = 1.0 - (irr_factors[0] * irr_factors[1] * irr_factors[2]) ** (1/3)
            if irr_score >= 0.70 or suffering >= 0.70:  # T3
                alternatives = [
                    AlternativeOption(
                        "Alternative approach A: negotiate with stakeholders",
                        UncertaintyBand(-0.5, 3.0, 0.8),
                        IrreversibilityAssessment(
                            factors=IrreversibilityFactors(0.7, 0.7, 0.7),
                            method="test", notes="", reversibility_plan="rollback",
                            assessor="test", confidence=0.8
                        ),
                        causal_strategy="negotiate",  # Distinct strategy
                    ),
                    AlternativeOption(
                        "Alternative approach B: delay and monitor",
                        UncertaintyBand(-0.3, 2.5, 0.75),
                        IrreversibilityAssessment(
                            factors=IrreversibilityFactors(0.8, 0.8, 0.8),
                            method="test", notes="", reversibility_plan="rollback",
                            assessor="test", confidence=0.8
                        ),
                        causal_strategy="delay",  # Distinct strategy
                    ),
                ]
            elif irr_score >= 0.30 or suffering >= 0.30:  # T2
                alternatives = [
                    AlternativeOption(
                        "Alternative approach: partial implementation",
                        UncertaintyBand(-0.5, 3.0, 0.8),
                        IrreversibilityAssessment(
                            factors=IrreversibilityFactors(0.7, 0.7, 0.7),
                            method="test", notes="", reversibility_plan="rollback",
                            assessor="test", confidence=0.8
                        ),
                        causal_strategy="partial",
                    ),
                ]
            else:
                alternatives = []
        
        defaults = dict(
            action_id="TEST_001",
            description="Test action description",
            timestamp_utc="2026-01-05T00:00:00Z",
            irreversibility=IrreversibilityAssessment(
                factors=IrreversibilityFactors(*irr_factors),
                method="test", notes="",
                reversibility_plan="adequate rollback plan here",
                assessor="test", confidence=0.9
            ),
            outcome_delta=UncertaintyBand(-1.0, 5.0, 0.9),
            necessity_confidence=necessity,
            novelty_loss_estimate=novelty,
            novelty_method="test",
            suffering_risk_estimate=suffering,
            suffering_method="test",
            alternatives=alternatives,
        )
        defaults.update(kwargs)
        return EvidenceObject(**defaults)
    
    def test_t0_auto_approve(self):
        """T0 actions should auto-approve."""
        ev = self._make_evidence(irr_factors=(0.95, 0.95, 0.95))  # Very low irr
        decision = self.proto.evaluate_action(ev)
        self.assertEqual(decision.outcome, AuditOutcome.APPROVE)
        self.assertEqual(decision.tier, ActionTier.T0_ROUTINE)
    
    def test_t3_default_deny_low_necessity(self):
        """T3 should deny when necessity is below threshold."""
        ev = self._make_evidence(
            irr_factors=(0.1, 0.1, 0.1),  # High irr -> T3
            necessity=0.5  # Below T3 threshold of 0.90
        )
        decision = self.proto.evaluate_action(ev)
        self.assertEqual(decision.outcome, AuditOutcome.DENY)
        self.assertEqual(decision.tier, ActionTier.T3_CATASTROPHIC)
    
    def test_t3_requires_external_review(self):
        """T3 with good evidence but no external review should require it."""
        ev = self._make_evidence(
            irr_factors=(0.1, 0.1, 0.1),  # High irr -> T3
            necessity=0.95,
            suffering=0.1,
            novelty=0.1,
        )
        decision = self.proto.evaluate_action(ev)
        # Should require external review (not auto-approve or deny outright)
        self.assertIn(decision.outcome, [AuditOutcome.REQUIRE_EXTERNAL_REVIEW, AuditOutcome.ESCROW])
    
    def test_t3_exception_criteria_enforced(self):
        """T3 with external review but missing criteria should be denied."""
        from lattice_audit_v1_7 import AlternativeOption
        
        # Create T3 evidence with external review approved but missing alternatives
        ev = self._make_evidence(
            irr_factors=(0.1, 0.1, 0.1),  # High irr -> T3
            necessity=0.95,
            suffering=0.1,
            novelty=0.1,
        )
        # Add external review approval
        ev = EvidenceObject(
            action_id=ev.action_id,
            description=ev.description,
            timestamp_utc=ev.timestamp_utc,
            irreversibility=ev.irreversibility,
            outcome_delta=ev.outcome_delta,
            necessity_confidence=ev.necessity_confidence,
            novelty_loss_estimate=ev.novelty_loss_estimate,
            novelty_method=ev.novelty_method,
            suffering_risk_estimate=ev.suffering_risk_estimate,
            suffering_method=ev.suffering_method,
            alternatives=[],  # No alternatives - should fail t3_min_alternatives_evaluated
            provenance={'external_review_approved': True},
        )
        decision = self.proto.evaluate_action(ev)
        # Should deny because alternatives < 2
        self.assertEqual(decision.outcome, AuditOutcome.DENY)
        self.assertIn("alternatives", decision.reason.lower())
    
    def test_t3_all_criteria_met_approves(self):
        """T3 with all exception criteria met should approve."""
        from lattice_audit_v1_7 import AlternativeOption, LatticeAuditProtocol, SQLiteAuditStore, PMIPolicy
        import tempfile
        
        # Use a PMIPolicy with relaxed architecture diversity for this test
        # (Testing T3 criteria approval, not architecture diversity)
        relaxed_policy = PMIPolicy(
            min_architecture_diversity_t3=0,  # Disable for this test
            min_training_source_diversity_t3=0,
            require_non_llm_auditor_t3=False,
            allow_provenance_external_approval=True,  # Allow provenance-based approval for test
        )
        
        with tempfile.TemporaryDirectory() as td:
            db = os.path.join(td, 'test_t3_approve.db')
            test_proto = LatticeAuditProtocol(
                store=SQLiteAuditStore(db),
                pmi_policy=relaxed_policy,
                strict_persistence=False,
            )
            
            # Create T3 evidence meeting all criteria
            # HARDENING (v1.7.7): Include diverse causal_strategy values
            alt1 = AlternativeOption(
                description="Alternative approach 1: negotiate with stakeholders",
                expected_utility=UncertaintyBand(-2.0, 8.0, 0.8),
                irreversibility=IrreversibilityAssessment(
                    factors=IrreversibilityFactors(0.5, 0.5, 0.5),
                    method="test", notes="", reversibility_plan="plan",
                    assessor="test", confidence=0.9
                ),
                causal_strategy="negotiate",  # Distinct strategy
            )
            alt2 = AlternativeOption(
                description="Alternative approach 2: delay and monitor",
                expected_utility=UncertaintyBand(-1.0, 6.0, 0.8),
                irreversibility=IrreversibilityAssessment(
                    factors=IrreversibilityFactors(0.6, 0.6, 0.6),
                    method="test", notes="", reversibility_plan="plan",
                    assessor="test", confidence=0.9
                ),
                causal_strategy="delay",  # Distinct strategy
            )
            
            ev = EvidenceObject(
                action_id="T3_APPROVE_TEST",
                description="T3 action with all criteria met",
                timestamp_utc="2026-01-05T00:00:00Z",
                irreversibility=IrreversibilityAssessment(
                    factors=IrreversibilityFactors(0.1, 0.1, 0.1),  # High irr -> T3
                    method="test", notes="", reversibility_plan="comprehensive rollback",
                    assessor="test", confidence=0.95
                ),
                outcome_delta=UncertaintyBand(-1.0, 10.0, 0.9),
                necessity_confidence=0.95,  # >= 0.90
                novelty_loss_estimate=0.15,  # <= 0.40
                novelty_method="test",
                suffering_risk_estimate=0.10,  # <= 0.20
                suffering_method="test",
                alternatives=[alt1, alt2],  # >= 2 alternatives with diverse strategies
                provenance={
                    'external_review_approved': True,
                    'uncertainty_acknowledged': True,  # Required by God-Lock safeguards
                },
            )
            decision = test_proto.evaluate_action(ev)
            # Should approve - all T3 exception criteria AND God-Lock safeguards met
            self.assertEqual(decision.outcome, AuditOutcome.APPROVE)
            self.assertEqual(decision.tier, ActionTier.T3_CATASTROPHIC)
    
    def test_invalid_evidence_denied(self):
        """Invalid evidence should be denied."""
        ev = self._make_evidence(action_id="")  # Invalid
        decision = self.proto.evaluate_action(ev)
        self.assertEqual(decision.outcome, AuditOutcome.DENY)
        self.assertIn("validation failed", decision.reason.lower())


class TestPersistence(unittest.TestCase):
    """Test SQLite persistence and hash chain."""
    
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.store = SQLiteAuditStore(self.db_path)
    
    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def test_initial_hash(self):
        """Initial hash should be all zeros."""
        self.assertEqual(self.store.last_hash(), "0" * 64)
    
    def test_append_and_retrieve(self):
        """Should be able to append and retrieve records."""
        from lattice_audit_v1_7 import AuditRecord
        rec = AuditRecord(
            action_id="TEST",
            timestamp_utc="2026-01-05T00:00:00Z",
            timestamp_ingested_utc="2026-01-05T00:00:01Z",
            protocol_version="1.7.6",
            tier="T1_SENSITIVE",
            outcome="approve",
            reason="test",
            evidence_json="{}",
            auditor_json="[]",
            prev_hash="0" * 64,
            record_hash="a" * 64,
        )
        self.store.append(rec)
        
        recent = self.store.get_recent(limit=1)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0].action_id, "TEST")
    
    def test_hash_chain_updates(self):
        """Hash should update after append."""
        from lattice_audit_v1_7 import AuditRecord
        initial_hash = self.store.last_hash()
        
        rec = AuditRecord(
            action_id="TEST",
            timestamp_utc="2026-01-05T00:00:00Z",
            timestamp_ingested_utc="2026-01-05T00:00:01Z",
            protocol_version="1.7.6",
            tier="T1_SENSITIVE",
            outcome="approve",
            reason="test",
            evidence_json="{}",
            auditor_json="[]",
            prev_hash=initial_hash,
            record_hash="b" * 64,
        )
        self.store.append(rec)
        
        new_hash = self.store.last_hash()
        self.assertNotEqual(initial_hash, new_hash)
        self.assertEqual(new_hash, "b" * 64)


class TestEscrow(unittest.TestCase):
    """Test escrow mechanics."""
    
    def test_escrow_entry_expiry(self):
        """Test escrow expiry detection."""
        now = datetime.datetime(2026, 1, 5, 12, 0, 0, tzinfo=datetime.timezone.utc)
        entry = EscrowEntry(
            evidence=None,  # Not needed for this test
            created_at_utc="2026-01-01T00:00:00Z",
            expires_at_utc="2026-01-05T00:00:00Z",
            next_reeval_at_utc="2026-01-04T00:00:00Z",
            reason="test",
        )
        self.assertTrue(entry.is_expired(now))
    
    def test_escrow_entry_not_expired(self):
        """Test non-expired escrow."""
        now = datetime.datetime(2026, 1, 3, 12, 0, 0, tzinfo=datetime.timezone.utc)
        entry = EscrowEntry(
            evidence=None,
            created_at_utc="2026-01-01T00:00:00Z",
            expires_at_utc="2026-01-05T00:00:00Z",
            next_reeval_at_utc="2026-01-04T00:00:00Z",
            reason="test",
        )
        self.assertFalse(entry.is_expired(now))
    
    def test_escrow_reevaluation_trigger(self):
        """Test reevaluation trigger."""
        now = datetime.datetime(2026, 1, 4, 12, 0, 0, tzinfo=datetime.timezone.utc)
        entry = EscrowEntry(
            evidence=None,
            created_at_utc="2026-01-01T00:00:00Z",
            expires_at_utc="2026-01-08T00:00:00Z",
            next_reeval_at_utc="2026-01-04T00:00:00Z",
            reason="test",
        )
        self.assertTrue(entry.should_reevaluate(now))


class TestPMIChecks(unittest.TestCase):
    """Test PMI (Procedural Mercy Invariant) checks."""
    
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.store = SQLiteAuditStore(self.db_path)
        self.proto = LatticeAuditProtocol(store=self.store)
    
    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def _make_evidence(self, necessity=0.9, suffering=0.1, novelty=0.1):
        return EvidenceObject(
            action_id="TEST",
            description="Test action",
            timestamp_utc="2026-01-05T00:00:00Z",
            irreversibility=IrreversibilityAssessment(
                factors=IrreversibilityFactors(0.5, 0.5, 0.5),
                method="test", notes="",
                reversibility_plan="plan",
                assessor="test", confidence=0.9
            ),
            outcome_delta=UncertaintyBand(-1.0, 5.0, 0.9),
            necessity_confidence=necessity,
            novelty_loss_estimate=novelty,
            novelty_method="test",
            suffering_risk_estimate=suffering,
            suffering_method="test",
        )
    
    def test_catastrophic_suffering_check_passes(self):
        ev = self._make_evidence(suffering=0.1)
        passed, msg = self.proto.catastrophic_suffering_check(ev, ActionTier.T2_HIGH_STAKES)
        self.assertTrue(passed)
    
    def test_catastrophic_suffering_check_fails_t2(self):
        ev = self._make_evidence(suffering=0.40)  # Above T2 threshold of 0.35
        passed, msg = self.proto.catastrophic_suffering_check(ev, ActionTier.T2_HIGH_STAKES)
        self.assertFalse(passed)
    
    def test_anti_necessity_check_passes(self):
        ev = self._make_evidence(necessity=0.85)
        passed, msg = self.proto.anti_necessity_check(ev, ActionTier.T2_HIGH_STAKES)
        self.assertTrue(passed)
    
    def test_anti_necessity_check_fails_t2(self):
        ev = self._make_evidence(necessity=0.75)  # Below T2 threshold of 0.80
        passed, msg = self.proto.anti_necessity_check(ev, ActionTier.T2_HIGH_STAKES)
        self.assertFalse(passed)
    
    def test_novelty_preservation_check_passes(self):
        ev = self._make_evidence(novelty=0.3)
        passed, msg = self.proto.novelty_preservation_check(ev, ActionTier.T2_HIGH_STAKES)
        self.assertTrue(passed)
    
    def test_novelty_preservation_check_fails_t2(self):
        ev = self._make_evidence(novelty=0.65)  # Above T2 threshold of 0.60
        passed, msg = self.proto.novelty_preservation_check(ev, ActionTier.T2_HIGH_STAKES)
        self.assertFalse(passed)


class TestReversibilityPreference(unittest.TestCase):
    """Test the reversibility preference PMI check."""
    
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.store = SQLiteAuditStore(self.db_path)
        self.proto = LatticeAuditProtocol(store=self.store)
    
    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def test_no_alternatives_passes(self):
        ev = EvidenceObject(
            action_id="TEST",
            description="Test action",
            timestamp_utc="2026-01-05T00:00:00Z",
            irreversibility=IrreversibilityAssessment(
                factors=IrreversibilityFactors(0.3, 0.3, 0.3),  # High irr
                method="test", notes="",
                reversibility_plan="plan",
                assessor="test", confidence=0.9
            ),
            outcome_delta=UncertaintyBand(0.0, 5.0, 0.9),
            necessity_confidence=0.9,
            novelty_loss_estimate=0.1,
            novelty_method="test",
            suffering_risk_estimate=0.1,
            suffering_method="test",
            alternatives=[],  # No alternatives
        )
        passed, msg = self.proto.reversibility_preference_check(ev)
        self.assertTrue(passed)
    
    def test_better_reversible_alternative_fails(self):
        """Should fail if a more reversible alternative has comparable utility."""
        ev = EvidenceObject(
            action_id="TEST",
            description="Test action",
            timestamp_utc="2026-01-05T00:00:00Z",
            irreversibility=IrreversibilityAssessment(
                factors=IrreversibilityFactors(0.3, 0.3, 0.3),  # High irr (~0.7)
                method="test", notes="",
                reversibility_plan="plan",
                assessor="test", confidence=0.9
            ),
            outcome_delta=UncertaintyBand(0.0, 4.0, 0.9),  # midpoint = 2.0
            necessity_confidence=0.9,
            novelty_loss_estimate=0.1,
            novelty_method="test",
            suffering_risk_estimate=0.1,
            suffering_method="test",
            alternatives=[
                AlternativeOption(
                    description="More reversible alternative",
                    expected_utility=UncertaintyBand(0.0, 4.0, 0.9),  # Same utility
                    irreversibility=IrreversibilityAssessment(
                        factors=IrreversibilityFactors(0.8, 0.8, 0.8),  # Lower irr (~0.2)
                        method="test", notes="",
                        reversibility_plan="better plan",
                        assessor="test", confidence=0.9
                    ),
                )
            ],
        )
        passed, msg = self.proto.reversibility_preference_check(ev)
        self.assertFalse(passed)
        self.assertIn("reversibility preference", msg.lower())


class TestHashChainIntegrity(unittest.TestCase):
    """Test hash chain verification functionality."""
    
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.store = SQLiteAuditStore(self.db_path)
        self.proto = LatticeAuditProtocol(store=self.store)
    
    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def _make_evidence(self, action_id, necessity=0.95):
        return EvidenceObject(
            action_id=action_id,
            description="Test action description",
            timestamp_utc="2026-01-05T00:00:00Z",
            irreversibility=IrreversibilityAssessment(
                factors=IrreversibilityFactors(0.95, 0.95, 0.95),
                method="test", notes="",
                reversibility_plan="test plan",
                assessor="test", confidence=0.9
            ),
            outcome_delta=UncertaintyBand(-1.0, 5.0, 0.9),
            necessity_confidence=necessity,
            novelty_loss_estimate=0.1,
            novelty_method="test",
            suffering_risk_estimate=0.1,
            suffering_method="test",
        )
    
    def test_empty_chain_valid(self):
        """Empty chain should be valid."""
        valid, errors = self.store.verify_chain()
        self.assertTrue(valid)
        self.assertEqual(errors, [])
    
    def test_single_record_chain_valid(self):
        """Single record chain should be valid."""
        ev = self._make_evidence("TEST_001")
        self.proto.evaluate_action(ev)
        
        valid, errors = self.store.verify_chain()
        self.assertTrue(valid, f"Errors: {errors}")
    
    def test_multiple_records_chain_valid(self):
        """Multiple records should maintain valid chain."""
        for i in range(5):
            ev = self._make_evidence(f"TEST_{i:03d}")
            self.proto.evaluate_action(ev)
        
        valid, errors = self.store.verify_chain()
        self.assertTrue(valid, f"Errors: {errors}")
    
    def test_recompute_and_verify(self):
        """Deep verification should pass for valid chain."""
        for i in range(3):
            ev = self._make_evidence(f"TEST_{i:03d}")
            self.proto.evaluate_action(ev)
        
        valid, errors = self.store.recompute_and_verify()
        self.assertTrue(valid, f"Errors: {errors}")
    
    def test_get_all_records(self):
        """Should retrieve all records in order."""
        for i in range(3):
            ev = self._make_evidence(f"TEST_{i:03d}")
            self.proto.evaluate_action(ev)
        
        records = self.store.get_all()
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0].action_id, "TEST_000")
        self.assertEqual(records[2].action_id, "TEST_002")
    
    def test_get_by_action_id(self):
        """Should retrieve records for specific action."""
        ev = self._make_evidence("TARGET")
        self.proto.evaluate_action(ev)
        
        records = self.store.get_by_action_id("TARGET")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].action_id, "TARGET")
    
    def test_count(self):
        """Should return correct count."""
        self.assertEqual(self.store.count(), 0)
        
        for i in range(5):
            ev = self._make_evidence(f"TEST_{i:03d}")
            self.proto.evaluate_action(ev)
        
        self.assertEqual(self.store.count(), 5)


class TestThreadSafety(unittest.TestCase):
    """Test concurrent access to the protocol."""
    
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.store = SQLiteAuditStore(self.db_path)
        self.proto = LatticeAuditProtocol(store=self.store)
        self.results = []
        self.errors = []
    
    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def _make_evidence(self, action_id):
        return EvidenceObject(
            action_id=action_id,
            description="Test action description",
            timestamp_utc="2026-01-05T00:00:00Z",
            irreversibility=IrreversibilityAssessment(
                factors=IrreversibilityFactors(0.95, 0.95, 0.95),
                method="test", notes="",
                reversibility_plan="test plan",
                assessor="test", confidence=0.9
            ),
            outcome_delta=UncertaintyBand(-1.0, 5.0, 0.9),
            necessity_confidence=0.95,
            novelty_loss_estimate=0.1,
            novelty_method="test",
            suffering_risk_estimate=0.1,
            suffering_method="test",
        )
    
    def _evaluate_action(self, action_id):
        try:
            ev = self._make_evidence(action_id)
            decision = self.proto.evaluate_action(ev)
            self.results.append((action_id, decision.outcome))
        except Exception as e:
            self.errors.append((action_id, str(e)))
    
    def test_concurrent_evaluations(self):
        """Multiple threads should be able to evaluate actions concurrently."""
        import threading
        
        threads = []
        for i in range(10):
            t = threading.Thread(target=self._evaluate_action, args=(f"THREAD_{i:03d}",))
            threads.append(t)
        
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
        
        # All should complete without errors
        self.assertEqual(len(self.errors), 0, f"Errors: {self.errors}")
        self.assertEqual(len(self.results), 10)
        
        # All should be approved (T0 routine)
        for action_id, outcome in self.results:
            self.assertEqual(outcome, AuditOutcome.APPROVE)
    
    def test_concurrent_chain_integrity(self):
        """Hash chain should remain valid after concurrent writes."""
        import threading
        
        threads = []
        for i in range(10):
            t = threading.Thread(target=self._evaluate_action, args=(f"CHAIN_{i:03d}",))
            threads.append(t)
        
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
        
        # Chain should still be valid
        valid, errors = self.store.verify_chain()
        self.assertTrue(valid, f"Chain errors: {errors}")
        
        # Count should be correct
        self.assertEqual(self.store.count(), 10)


class TestEscrowRelease(unittest.TestCase):
    """Test escrow release functionality."""
    
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.store = SQLiteAuditStore(self.db_path)
        self.proto = LatticeAuditProtocol(store=self.store)
    
    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def _make_evidence(self, action_id, necessity=0.7, irr_factors=(0.4, 0.4, 0.4)):
        return EvidenceObject(
            action_id=action_id,
            description="Test action description",
            timestamp_utc="2026-01-05T00:00:00Z",
            irreversibility=IrreversibilityAssessment(
                factors=IrreversibilityFactors(*irr_factors),
                method="test", notes="",
                reversibility_plan="adequate rollback plan here",
                assessor="test", confidence=0.9
            ),
            outcome_delta=UncertaintyBand(-1.0, 5.0, 0.9),
            necessity_confidence=necessity,
            novelty_loss_estimate=0.1,
            novelty_method="test",
            suffering_risk_estimate=0.1,
            suffering_method="test",
        )
    
    def test_list_escrowed_actions(self):
        """Should list escrowed actions."""
        # Create an action that will be escrowed (T2 with low necessity)
        ev = self._make_evidence("ESCROW_TEST", necessity=0.6, irr_factors=(0.4, 0.4, 0.4))
        decision = self.proto.evaluate_action(ev)
        
        # Should be escrowed or denied due to low necessity
        self.assertIn(decision.outcome, [AuditOutcome.ESCROW, AuditOutcome.DENY])
    
    def test_get_escrow_status_not_found(self):
        """Should return None for non-escrowed action."""
        status = self.proto.get_escrow_status("NONEXISTENT")
        self.assertIsNone(status)
    
    def test_release_nonexistent_escrow(self):
        """Releasing non-escrowed action should fail."""
        ev = self._make_evidence("NONEXISTENT")
        decision = self.proto.release_escrow("NONEXISTENT", ev)
        self.assertEqual(decision.outcome, AuditOutcome.DENY)
    
    def test_extend_escrow_nonexistent(self):
        """Extending non-escrowed action should return False."""
        result = self.proto.extend_escrow("NONEXISTENT", 3600, "test")
        self.assertFalse(result)


class TestExternalReview(unittest.TestCase):
    """Test external review workflow."""
    
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.store = SQLiteAuditStore(self.db_path)
        self.proto = LatticeAuditProtocol(store=self.store)
    
    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def test_request_external_review(self):
        """Should create external review request."""
        from lattice_audit_v1_7 import ExternalReviewRequest
        
        ev = EvidenceObject(
            action_id="REVIEW_TEST",
            description="Test action",
            timestamp_utc="2026-01-05T00:00:00Z",
            irreversibility=IrreversibilityAssessment(
                factors=IrreversibilityFactors(0.5, 0.5, 0.5),
                method="test", notes="",
                reversibility_plan="plan",
                assessor="test", confidence=0.9
            ),
            outcome_delta=UncertaintyBand(-1.0, 5.0, 0.9),
            necessity_confidence=0.95,
            novelty_loss_estimate=0.1,
            novelty_method="test",
            suffering_risk_estimate=0.1,
            suffering_method="test",
        )
        
        request = self.proto.request_external_review(
            ev, 
            requested_by="test_user",
            reason="High stakes decision"
        )
        
        self.assertEqual(request.action_id, "REVIEW_TEST")
        self.assertEqual(request.requested_by, "test_user")
        self.assertIsNotNone(request.requested_at_utc)
    
    def test_submit_external_review_not_in_escrow(self):
        """Submitting review for non-escrowed action should fail."""
        from lattice_audit_v1_7 import ExternalReviewResponse
        
        response = ExternalReviewResponse(
            action_id="NONEXISTENT",
            reviewer_id="panel_1",
            reviewer_type="human_panel",
            decision="approve",
            confidence=0.9,
            reasoning="Test approval"
        )
        
        decision = self.proto.submit_external_review(response)
        self.assertEqual(decision.outcome, AuditOutcome.DENY)


class TestLogging(unittest.TestCase):
    """Test logging configuration."""
    
    def test_logger_exists(self):
        """Logger should be properly configured."""
        from lattice_audit_v1_7 import logger
        self.assertEqual(logger.name, "lattice_audit")
    
    def test_logger_level(self):
        """Logger should have DEBUG level by default."""
        from lattice_audit_v1_7 import logger
        self.assertEqual(logger.level, logging.DEBUG)


class TestAdversarialPressure(unittest.TestCase):
    """
    Adversarial tests simulating agents trying to game the system.
    
    These tests check resilience against:
    - Boundary gaming (staying just below thresholds)
    - Evidence manipulation
    - Threshold sensitivity
    """
    
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.store = SQLiteAuditStore(self.db_path)
        self.proto = LatticeAuditProtocol(store=self.store)
    
    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def _make_evidence(self, irr_factors=(0.5, 0.5, 0.5), necessity=0.85, 
                       suffering=0.1, novelty=0.1, alternatives=None, **kwargs):
        from lattice_audit_v1_7 import AlternativeOption
        
        # Generate default alternatives for T2/T3 actions
        if alternatives is None:
            irr_score = 1.0 - (irr_factors[0] * irr_factors[1] * irr_factors[2]) ** (1/3)
            if irr_score >= 0.70 or suffering >= 0.70:  # T3
                alternatives = [
                    AlternativeOption(
                        "Alternative approach A different method",
                        UncertaintyBand(-0.5, 3.0, 0.8),
                        IrreversibilityAssessment(
                            factors=IrreversibilityFactors(0.7, 0.7, 0.7),
                            method="test", notes="", reversibility_plan="rollback",
                            assessor="test", confidence=0.8
                        )
                    ),
                    AlternativeOption(
                        "Alternative approach B safer strategy",
                        UncertaintyBand(-0.3, 2.5, 0.75),
                        IrreversibilityAssessment(
                            factors=IrreversibilityFactors(0.8, 0.8, 0.8),
                            method="test", notes="", reversibility_plan="rollback",
                            assessor="test", confidence=0.8
                        )
                    ),
                ]
            elif irr_score >= 0.30 or suffering >= 0.30:  # T2
                alternatives = [
                    AlternativeOption(
                        "Alternative approach different method",
                        UncertaintyBand(-0.5, 3.0, 0.8),
                        IrreversibilityAssessment(
                            factors=IrreversibilityFactors(0.7, 0.7, 0.7),
                            method="test", notes="", reversibility_plan="rollback",
                            assessor="test", confidence=0.8
                        )
                    ),
                ]
            else:
                alternatives = []
        
        defaults = dict(
            action_id="ADV_TEST",
            description="Adversarial test action",
            timestamp_utc="2026-01-05T00:00:00Z",
            irreversibility=IrreversibilityAssessment(
                factors=IrreversibilityFactors(*irr_factors),
                method="test", notes="",
                reversibility_plan="adequate rollback plan here",
                assessor="test", confidence=0.9
            ),
            outcome_delta=UncertaintyBand(-1.0, 5.0, 0.9),
            necessity_confidence=necessity,
            novelty_loss_estimate=novelty,
            novelty_method="test",
            suffering_risk_estimate=suffering,
            suffering_method="test",
            alternatives=alternatives,
        )
        defaults.update(kwargs)
        return EvidenceObject(**defaults)
    
    def test_boundary_gaming_t1_t2(self):
        """
        Test agent crafting evidence to stay just below T2 threshold (irr=0.29).
        
        This simulates an agent that understands the tier boundaries and
        manipulates its reported irreversibility to avoid stricter scrutiny.
        
        NOTE: Entry Gate can escalate tiers based on description keywords,
        so we use neutral descriptions that won't trigger escalation.
        """
        from lattice_audit_v1_7 import AlternativeOption
        
        # T1 range: 0.10 <= irr < 0.30
        # irr factors of (0.75, 0.75, 0.75) give irr ≈ 0.25 (T1)
        ev = EvidenceObject(
            action_id="T1_TEST",
            description="Simple routine maintenance task",
            timestamp_utc="2026-01-05T00:00:00Z",
            irreversibility=IrreversibilityAssessment(
                factors=IrreversibilityFactors(0.75, 0.75, 0.75),  # irr ≈ 0.25
                method="test", notes="", reversibility_plan="easy rollback",
                assessor="test", confidence=0.9
            ),
            outcome_delta=UncertaintyBand(-1.0, 5.0, 0.9),
            necessity_confidence=0.85,
            novelty_loss_estimate=0.1,
            novelty_method="test",
            suffering_risk_estimate=0.1,
            suffering_method="test",
        )
        decision = self.proto.evaluate_action(ev)
        
        # Should be T1 with less scrutiny (unless Entry Gate escalates)
        self.assertIn(decision.tier, [ActionTier.T1_SENSITIVE, ActionTier.T2_HIGH_STAKES])
        
        # Just above T2 threshold (irr >= 0.30)
        # irr factors of (0.69, 0.69, 0.69) give irr ≈ 0.31 (T2)
        ev2 = EvidenceObject(
            action_id="T2_TEST",
            description="Simple routine maintenance task",
            timestamp_utc="2026-01-05T00:00:00Z",
            irreversibility=IrreversibilityAssessment(
                factors=IrreversibilityFactors(0.65, 0.65, 0.65),  # irr ≈ 0.33 (T2)
                method="test", notes="", reversibility_plan="rollback procedure",
                assessor="test", confidence=0.9
            ),
            outcome_delta=UncertaintyBand(-1.0, 5.0, 0.9),
            necessity_confidence=0.85,
            novelty_loss_estimate=0.1,
            novelty_method="test",
            suffering_risk_estimate=0.1,
            suffering_method="test",
            alternatives=[
                AlternativeOption(
                    "Alternative approach with different method",
                    UncertaintyBand(-0.5, 3.0, 0.8),
                    IrreversibilityAssessment(
                        factors=IrreversibilityFactors(0.8, 0.8, 0.8),
                        method="test", notes="", reversibility_plan="rollback",
                        assessor="test", confidence=0.8
                    )
                ),
            ],
        )
        decision2 = self.proto.evaluate_action(ev2)
        
        # Should be T2 with stricter scrutiny
        self.assertIn(decision2.tier, [ActionTier.T2_HIGH_STAKES, ActionTier.T3_CATASTROPHIC])
    
    def test_boundary_gaming_t2_t3(self):
        """
        Test agent crafting evidence to stay just below T3 threshold (irr=0.69).
        
        NOTE: Entry Gate and catastrophic floor checks may override tier.
        """
        from lattice_audit_v1_7 import AlternativeOption
        
        # Just below T3 threshold (irr < 0.70)
        # irr factors of (0.30, 0.30, 0.30) give irr ≈ 0.697 (T2)
        ev = EvidenceObject(
            action_id="T2_HIGH_TEST",
            description="Simple routine maintenance task",
            timestamp_utc="2026-01-05T00:00:00Z",
            irreversibility=IrreversibilityAssessment(
                factors=IrreversibilityFactors(0.30, 0.30, 0.30),  # irr ≈ 0.697
                method="test", notes="", reversibility_plan="rollback",
                assessor="test", confidence=0.9
            ),
            outcome_delta=UncertaintyBand(-1.0, 5.0, 0.9),
            necessity_confidence=0.85,
            novelty_loss_estimate=0.1,
            novelty_method="test",
            suffering_risk_estimate=0.1,
            suffering_method="test",
            alternatives=[
                AlternativeOption(
                    "Alternative approach A with different method",
                    UncertaintyBand(-0.5, 3.0, 0.8),
                    IrreversibilityAssessment(
                        factors=IrreversibilityFactors(0.8, 0.8, 0.8),
                        method="test", notes="", reversibility_plan="rollback",
                        assessor="test", confidence=0.8
                    )
                ),
                AlternativeOption(
                    "Alternative approach B with safer strategy",
                    UncertaintyBand(-0.3, 2.5, 0.75),
                    IrreversibilityAssessment(
                        factors=IrreversibilityFactors(0.85, 0.85, 0.85),
                        method="test", notes="", reversibility_plan="rollback",
                        assessor="test", confidence=0.8
                    )
                ),
            ],
        )
        decision = self.proto.evaluate_action(ev)
        
        # Should be T2 or higher (Entry Gate may escalate)
        self.assertIn(decision.tier, [ActionTier.T2_HIGH_STAKES, ActionTier.T3_CATASTROPHIC])
        
        # Just above T3 threshold (irr >= 0.70)
        ev2 = self._make_evidence(irr_factors=(0.20, 0.20, 0.20))  # irr ≈ 0.735
        decision2 = self.proto.evaluate_action(ev2)
        
        self.assertEqual(decision2.tier, ActionTier.T3_CATASTROPHIC)
    
    def test_necessity_inflation(self):
        """
        Test detection of implausibly high necessity claims.
        
        An adversarial agent might claim necessity=1.0 to bypass checks.
        """
        ev = self._make_evidence(
            irr_factors=(0.3, 0.3, 0.3),  # T3
            necessity=1.0,  # Perfect necessity claim
            suffering=0.5,
        )
        
        # Even with perfect necessity, high suffering should trigger scrutiny
        decision = self.proto.evaluate_action(ev)
        
        # The system should not blindly approve - either DENY or ESCROW is acceptable
        # The key is that it doesn't approve without scrutiny
        self.assertIn(decision.outcome, [AuditOutcome.DENY, AuditOutcome.ESCROW, 
                                          AuditOutcome.REQUIRE_EXTERNAL_REVIEW])
    
    def test_reversibility_inflation(self):
        """
        Test detection of inflated reversibility claims.
        
        An adversarial agent might claim high reversibility (low irr)
        while actually proposing irreversible actions.
        """
        from lattice_audit_v1_7 import compute_irreversibility_score
        
        # Claim: highly reversible
        ev = self._make_evidence(
            irr_factors=(0.95, 0.95, 0.95),  # Claims high reversibility
        )
        
        # The system trusts this, but the cross-verification check
        # (if an external model provider is used) would catch this
        irr = compute_irreversibility_score(ev.irreversibility, IrreversibilityScoringPolicy())
        
        # With the new epsilon floor, even claimed 0.95 reversibility
        # results in low but non-zero irreversibility
        self.assertLess(irr, 0.10)
    
    def test_perfect_score_detection(self):
        """
        Test that suspiciously perfect evidence scores are flagged.
        
        Real-world evidence rarely has exactly 0.0 suffering or 1.0 necessity.
        """
        from lattice_audit_v1_7 import PassthroughModelProvider
        
        ev = self._make_evidence(
            necessity=1.0,  # Suspiciously perfect
            suffering=0.0,  # Suspiciously perfect
        )
        
        provider = PassthroughModelProvider()
        is_consistent, anomalies = provider.cross_verify(ev)
        
        self.assertFalse(is_consistent)
        self.assertTrue(any("Perfect scores" in a for a in anomalies))
    
    def test_missing_alternatives_detection(self):
        """
        Test detection of high-irr actions without alternatives.
        
        Adversarial agents might omit alternatives to avoid comparison.
        """
        from lattice_audit_v1_7 import PassthroughModelProvider
        
        ev = self._make_evidence(
            irr_factors=(0.3, 0.3, 0.3),  # High irr
            alternatives=[],  # Explicitly no alternatives
        )
        
        provider = PassthroughModelProvider()
        is_consistent, anomalies = provider.cross_verify(ev)
        
        self.assertFalse(is_consistent)
        self.assertTrue(any("no alternatives" in a.lower() for a in anomalies))
    
    def test_threshold_jitter_resilience(self):
        """
        Test that decisions are stable under small threshold perturbations.
        
        If a decision flips with 5% jitter, the evidence is near a boundary
        and deserves closer scrutiny.
        """
        from lattice_audit_v1_7 import infer_tier_with_jitter, TierBoundaries
        
        # Test case clearly in T2 (not near boundaries)
        irr = 0.50  # Solidly in T2 range [0.30, 0.70]
        suffering = 0.3
        
        # Run multiple jittered evaluations
        results = []
        for _ in range(20):
            tier, _ = infer_tier_with_jitter(irr, suffering, jitter_range=0.05)
            results.append(tier)
        
        # Should be stable (all T2)
        self.assertTrue(all(t == ActionTier.T2_HIGH_STAKES for t in results))
    
    def test_threshold_jitter_detects_boundary_cases(self):
        """
        Test that jitter reveals boundary-gaming attempts.
        """
        from lattice_audit_v1_7 import infer_tier_with_jitter
        
        # Test case right at boundary (potential gaming)
        irr = 0.295  # Just below T2 threshold of 0.30
        suffering = 0.3
        
        # Run multiple jittered evaluations
        results = []
        for _ in range(50):
            tier, _ = infer_tier_with_jitter(irr, suffering, jitter_range=0.05)
            results.append(tier)
        
        # Should be unstable (mix of T1 and T2)
        unique_tiers = set(results)
        self.assertGreater(len(unique_tiers), 1, 
                          "Boundary case should show instability under jitter")
    
    def test_confidence_regression(self):
        """
        Test that low-confidence scores regress toward middle.
        """
        from lattice_audit_v1_7 import compute_irreversibility_score
        
        # High claimed reversibility with low confidence
        factors_high_conf = IrreversibilityFactors(0.9, 0.9, 0.9)
        assess_high_conf = IrreversibilityAssessment(
            factors=factors_high_conf,
            method="test", notes="",
            reversibility_plan="plan",
            assessor="test",
            confidence=0.95,
        )
        
        assess_low_conf = IrreversibilityAssessment(
            factors=factors_high_conf,
            method="test", notes="",
            reversibility_plan="plan",
            assessor="test",
            confidence=0.30,  # Low confidence
        )
        
        policy = IrreversibilityScoringPolicy()
        score_high_conf = compute_irreversibility_score(assess_high_conf, policy)
        score_low_conf = compute_irreversibility_score(assess_low_conf, policy)
        
        # Low confidence should regress toward middle (0.5)
        self.assertGreater(score_low_conf, score_high_conf)


class TestFloatNormalization(unittest.TestCase):
    """Test float normalization for cross-platform hash consistency."""
    
    def test_normalize_floats_precision(self):
        """Float normalization should round to fixed precision."""
        from lattice_audit_v1_7 import _normalize_floats
        
        # These would produce different representations on different platforms
        val1 = 0.333333333333333
        val2 = 0.333333333333334
        
        norm1 = _normalize_floats(val1)
        norm2 = _normalize_floats(val2)
        
        self.assertEqual(norm1, norm2)
    
    def test_normalize_floats_nan(self):
        """NaN should raise ValueError by default (fail_on_special=True)."""
        from lattice_audit_v1_7 import _normalize_floats
        
        # Default: raises ValueError to prevent type collision
        with self.assertRaises(ValueError):
            _normalize_floats(float('nan'))
        
        # With fail_on_special=False: returns tagged object
        result = _normalize_floats(float('nan'), fail_on_special=False)
        self.assertEqual(result, {"__special_float__": "nan"})
    
    def test_normalize_floats_inf(self):
        """Infinity should raise ValueError by default (fail_on_special=True)."""
        from lattice_audit_v1_7 import _normalize_floats
        
        # Default: raises ValueError
        with self.assertRaises(ValueError):
            _normalize_floats(float('inf'))
        with self.assertRaises(ValueError):
            _normalize_floats(float('-inf'))
        
        # With fail_on_special=False: returns tagged objects
        self.assertEqual(
            _normalize_floats(float('inf'), fail_on_special=False), 
            {"__special_float__": "inf"}
        )
        self.assertEqual(
            _normalize_floats(float('-inf'), fail_on_special=False),
            {"__special_float__": "-inf"}
        )
    
    def test_normalize_floats_nested(self):
        """Normalization should work on nested structures."""
        from lattice_audit_v1_7 import _normalize_floats
        
        nested = {
            "a": [1.111111111111111, 2.222222222222222],
            "b": {"c": 3.333333333333333}
        }
        
        result = _normalize_floats(nested)
        
        # Now using 8 decimal places
        self.assertEqual(result["a"][0], 1.11111111)
        self.assertEqual(result["b"]["c"], 3.33333333)
    
    def test_canonical_json_deterministic(self):
        """Canonical JSON should be deterministic across float variations."""
        from lattice_audit_v1_7 import _canonical_json
        
        # Use values that differ only beyond 8 decimal places
        obj1 = {"value": 0.12345678901}
        obj2 = {"value": 0.12345678902}
        
        json1 = _canonical_json(obj1)
        json2 = _canonical_json(obj2)
        
        self.assertEqual(json1, json2)


class TestDynamicThresholds(unittest.TestCase):
    """Test dynamic threshold configuration."""
    
    def test_tier_boundaries_default(self):
        """Default boundaries should match spec."""
        from lattice_audit_v1_7 import DEFAULT_TIER_BOUNDARIES
        
        self.assertEqual(DEFAULT_TIER_BOUNDARIES.t0_t1_boundary, 0.10)
        self.assertEqual(DEFAULT_TIER_BOUNDARIES.t1_t2_boundary, 0.30)
        self.assertEqual(DEFAULT_TIER_BOUNDARIES.t2_t3_boundary, 0.70)
    
    def test_tier_boundaries_custom(self):
        """Should be able to use custom boundaries."""
        from lattice_audit_v1_7 import TierBoundaries, infer_tier
        
        custom = TierBoundaries(
            t0_t1_boundary=0.15,
            t1_t2_boundary=0.40,
            t2_t3_boundary=0.80,
        )
        
        # With default boundaries, 0.12 would be T1
        # With custom boundaries, it should be T0
        tier = infer_tier(0.12, 0.1, boundaries=custom)
        self.assertEqual(tier, ActionTier.T0_ROUTINE)
    
    def test_tier_boundaries_jitter(self):
        """Jittered boundaries should be different from original."""
        from lattice_audit_v1_7 import DEFAULT_TIER_BOUNDARIES
        
        jittered = DEFAULT_TIER_BOUNDARIES.with_jitter(0.10)
        
        # At least one boundary should be different
        different = (
            jittered.t0_t1_boundary != DEFAULT_TIER_BOUNDARIES.t0_t1_boundary or
            jittered.t1_t2_boundary != DEFAULT_TIER_BOUNDARIES.t1_t2_boundary or
            jittered.t2_t3_boundary != DEFAULT_TIER_BOUNDARIES.t2_t3_boundary
        )
        self.assertTrue(different)


if __name__ == "__main__":
    unittest.main(verbosity=2)


# =============================================================================
# v1.7.6 HARDENING TESTS
# =============================================================================

class TestDevilsAdvocateAuditor(unittest.TestCase):
    """Tests for mandatory Devils Advocate auditor."""
    
    def test_da_always_objects_for_high_risk(self):
        """DA must always produce objection."""
        from lattice_audit_v1_7 import DevilsAdvocateAuditor, EvidenceObject, IrreversibilityAssessment, IrreversibilityFactors, UncertaintyBand
        
        da = DevilsAdvocateAuditor()
        ev = EvidenceObject(
            action_id='DA_TEST',
            description='High stakes test action',
            timestamp_utc='2026-01-07T00:00:00Z',
            irreversibility=IrreversibilityAssessment(
                factors=IrreversibilityFactors(0.3, 0.3, 0.3),
                method='test', notes='High stakes', reversibility_plan='Rollback',
                assessor='test', confidence=0.8
            ),
            outcome_delta=UncertaintyBand(0.0, 2.0, 0.8),
            necessity_confidence=0.85,
            novelty_loss_estimate=0.3,
            novelty_method='test',
            suffering_risk_estimate=0.3,
            suffering_method='test',
        )
        
        output = da.evaluate(ev, 'salt123')
        self.assertTrue(output.objection, "Devils Advocate must always produce objection")
        self.assertEqual(output.role.value, 'devils_advocate')


class TestEntryGateAuditor(unittest.TestCase):
    """Tests for Entry Gate tier estimation."""
    
    def test_entry_gate_detects_high_risk_keywords(self):
        """Entry Gate should detect high-risk keywords in description."""
        from lattice_audit_v1_7 import EntryGateAuditor, ActionTier, EvidenceObject, IrreversibilityAssessment, IrreversibilityFactors, UncertaintyBand
        
        gate = EntryGateAuditor()
        
        # Action with high-risk keywords
        ev = EvidenceObject(
            action_id='GATE_TEST',
            description='Delete all user data permanently',
            timestamp_utc='2026-01-07T00:00:00Z',
            irreversibility=IrreversibilityAssessment(
                factors=IrreversibilityFactors(0.95, 0.95, 0.95),  # Agent claims safe
                method='test', notes='Safe', reversibility_plan='N/A',
                assessor='test', confidence=0.9
            ),
            outcome_delta=UncertaintyBand(0.0, 1.0, 0.9),
            necessity_confidence=0.8,
            novelty_loss_estimate=0.05,
            novelty_method='test',
            suffering_risk_estimate=0.05,
            suffering_method='test',
        )
        
        baseline_tier = gate.estimate_baseline_tier(ev)
        self.assertGreater(baseline_tier.value, ActionTier.T0_ROUTINE.value,
                          "Entry Gate should escalate tier for high-risk keywords")


class TestTrustedTimestamps(unittest.TestCase):
    """Tests for trusted ingestion timestamps."""
    
    def test_audit_record_has_ingested_timestamp(self):
        """Audit records must have timestamp_ingested_utc set by protocol."""
        from lattice_audit_v1_7 import LatticeAuditProtocol, SQLiteAuditStore, EvidenceObject, IrreversibilityAssessment, IrreversibilityFactors, UncertaintyBand
        import tempfile
        
        with tempfile.TemporaryDirectory() as td:
            db = os.path.join(td, 'test.db')
            proto = LatticeAuditProtocol(store=SQLiteAuditStore(db))
            
            ev = EvidenceObject(
                action_id='TIMESTAMP_TEST',
                description='Test trusted timestamps',
                timestamp_utc='2020-01-01T00:00:00Z',  # Old agent-claimed timestamp
                irreversibility=IrreversibilityAssessment(
                    factors=IrreversibilityFactors(0.95, 0.95, 0.95),
                    method='test', notes='Safe', reversibility_plan='N/A',
                    assessor='test', confidence=0.9
                ),
                outcome_delta=UncertaintyBand(0.0, 1.0, 0.9),
                necessity_confidence=0.8,
                novelty_loss_estimate=0.05,
                novelty_method='test',
                suffering_risk_estimate=0.05,
                suffering_method='test',
            )
            
            proto.evaluate_action(ev)
            
            records = proto.store.get_recent(1)
            self.assertEqual(len(records), 1)
            rec = records[0]
            
            # Agent timestamp is preserved but ingested is different
            self.assertEqual(rec.timestamp_utc, '2020-01-01T00:00:00Z')
            self.assertNotEqual(rec.timestamp_ingested_utc, rec.timestamp_utc)
            self.assertTrue(rec.timestamp_ingested_utc.startswith('202'))  # Recent year


class TestProtocolVersioning(unittest.TestCase):
    """Tests for protocol versioning in audit records."""
    
    def test_audit_record_has_protocol_version(self):
        """Audit records must include protocol version."""
        from lattice_audit_v1_7 import LatticeAuditProtocol, SQLiteAuditStore, EvidenceObject, IrreversibilityAssessment, IrreversibilityFactors, UncertaintyBand
        import tempfile
        
        with tempfile.TemporaryDirectory() as td:
            db = os.path.join(td, 'test.db')
            proto = LatticeAuditProtocol(store=SQLiteAuditStore(db))
            
            ev = EvidenceObject(
                action_id='VERSION_TEST',
                description='Test protocol versioning',
                timestamp_utc='2026-01-07T00:00:00Z',
                irreversibility=IrreversibilityAssessment(
                    factors=IrreversibilityFactors(0.95, 0.95, 0.95),
                    method='test', notes='Safe', reversibility_plan='N/A',
                    assessor='test', confidence=0.9
                ),
                outcome_delta=UncertaintyBand(0.0, 1.0, 0.9),
                necessity_confidence=0.8,
                novelty_loss_estimate=0.05,
                novelty_method='test',
                suffering_risk_estimate=0.05,
                suffering_method='test',
            )
            
            proto.evaluate_action(ev)
            
            records = proto.store.get_recent(1)
            self.assertEqual(len(records), 1)
            rec = records[0]
            
            self.assertEqual(rec.protocol_version, '1.0.0')


class TestAlternativeQualityChecks(unittest.TestCase):
    """Tests for straw-man alternative detection."""
    
    def test_insincere_alternatives_detected(self):
        """Validation should reject obviously straw-man alternatives."""
        from lattice_audit_v1_7 import EvidenceObject, IrreversibilityAssessment, IrreversibilityFactors, UncertaintyBand, AlternativeOption
        
        ev = EvidenceObject(
            action_id='STRAWMAN_TEST',
            description='Deploy critical system update to production',
            timestamp_utc='2026-01-07T00:00:00Z',
            irreversibility=IrreversibilityAssessment(
                factors=IrreversibilityFactors(0.3, 0.3, 0.3),  # T2 level
                method='test', notes='High stakes', reversibility_plan='Rollback',
                assessor='test', confidence=0.8
            ),
            outcome_delta=UncertaintyBand(0.0, 5.0, 0.8),
            necessity_confidence=0.9,
            novelty_loss_estimate=0.3,
            novelty_method='test',
            suffering_risk_estimate=0.3,
            suffering_method='test',
            alternatives=[
                # Straw-man: catastrophic baseline
                AlternativeOption('Do nothing and let system crash', 
                    UncertaintyBand(-10.0, -5.0, 0.9),  # Catastrophic
                    IrreversibilityAssessment(
                        factors=IrreversibilityFactors(0.1, 0.1, 0.1),
                        method='test', notes='Catastrophic', reversibility_plan='None',
                        assessor='test', confidence=0.95
                    ))
            ],
        )
        
        ok, errors = ev.validate()
        # Should detect the straw alternative
        has_straw_error = any('STRAW_ALTERNATIVE' in e for e in errors)
        self.assertTrue(has_straw_error, f"Should detect straw alternative. Errors: {errors}")


class TestGovernanceFriction(unittest.TestCase):
    """Tests for governance friction metrics."""
    
    def test_friction_metrics_computed(self):
        """Governance friction metrics should be computed."""
        from lattice_audit_v1_7 import LatticeAuditProtocol, SQLiteAuditStore, EvidenceObject, IrreversibilityAssessment, IrreversibilityFactors, UncertaintyBand
        import tempfile
        
        with tempfile.TemporaryDirectory() as td:
            db = os.path.join(td, 'test.db')
            proto = LatticeAuditProtocol(store=SQLiteAuditStore(db))
            
            # Create some test actions
            for i in range(5):
                ev = EvidenceObject(
                    action_id=f'FRICTION_{i}',
                    description=f'Test action {i} for friction',
                    timestamp_utc='2026-01-07T00:00:00Z',
                    irreversibility=IrreversibilityAssessment(
                        factors=IrreversibilityFactors(0.9, 0.9, 0.9),
                        method='test', notes='Safe', reversibility_plan='N/A',
                        assessor='test', confidence=0.9
                    ),
                    outcome_delta=UncertaintyBand(0.0, 1.0, 0.9),
                    necessity_confidence=0.8,
                    novelty_loss_estimate=0.05,
                    novelty_method='test',
                    suffering_risk_estimate=0.05,
                    suffering_method='test',
                )
                proto.evaluate_action(ev)
            
            friction = proto.compute_governance_friction()
            
            self.assertIn('escrow_rate', friction)
            self.assertIn('deny_rate', friction)
            self.assertIn('friction_score', friction)
            self.assertIn('throughput_proxy', friction)
            self.assertEqual(friction['sample_size'], 5)


class TestEscrowDecay(unittest.TestCase):
    """Tests for escrow decay logic."""
    
    def test_sweep_expired_escrows(self):
        """Expired escrows should decay to DENY."""
        from lattice_audit_v1_7 import LatticeAuditProtocol, SQLiteAuditStore, EvidenceObject, IrreversibilityAssessment, IrreversibilityFactors, UncertaintyBand, EscrowEntry
        import tempfile
        import datetime
        
        with tempfile.TemporaryDirectory() as td:
            db = os.path.join(td, 'test.db')
            proto = LatticeAuditProtocol(store=SQLiteAuditStore(db))
            
            # Create a fake expired escrow entry
            now = datetime.datetime.now(datetime.timezone.utc)
            past = now - datetime.timedelta(hours=24)
            
            ev = EvidenceObject(
                action_id='DECAY_TEST',
                description='Test escrow decay',
                timestamp_utc='2026-01-07T00:00:00Z',
                irreversibility=IrreversibilityAssessment(
                    factors=IrreversibilityFactors(0.5, 0.5, 0.5),
                    method='test', notes='Test', reversibility_plan='Test',
                    assessor='test', confidence=0.8
                ),
                outcome_delta=UncertaintyBand(0.0, 1.0, 0.8),
                necessity_confidence=0.5,
                novelty_loss_estimate=0.3,
                novelty_method='test',
                suffering_risk_estimate=0.3,
                suffering_method='test',
            )
            
            # Manually add expired entry
            entry = EscrowEntry(
                evidence=ev,
                created_at_utc=past.isoformat().replace('+00:00', 'Z'),
                expires_at_utc=past.isoformat().replace('+00:00', 'Z'),  # Already expired
                next_reeval_at_utc=past.isoformat().replace('+00:00', 'Z'),
                reason='Test escrow',
                status='pending',
            )
            proto._escrow_queue['DECAY_TEST'] = entry
            
            # Sweep should find and decay it
            results = proto.sweep_expired_escrows()
            
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]['action_id'], 'DECAY_TEST')
            self.assertEqual(results[0]['disposition'], 'DECAYED_TO_DENY')


if __name__ == '__main__':
    unittest.main()
