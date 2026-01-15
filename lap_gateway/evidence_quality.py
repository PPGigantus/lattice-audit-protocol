"""
LAP Evidence Quality Module (v2.0)

Minimum Information Density (MID) checks to prevent "semantic minimalism" attacks
where an agent provides technically valid but context-free evidence.

Security Properties:
- Enforces minimum description length
- Enforces minimum entropy (information density)
- Validates reversibility_plan is meaningful
- Checks alternatives have substantive descriptions
- Rejects copy-paste/repetitive content

This prevents approval of "black box" requests where human reviewers
see valid JSON structure but no meaningful context.
"""

import math
import re
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict, Any
from collections import Counter


@dataclass
class EvidenceQualityPolicy:
    """
    Policy for minimum evidence quality requirements.
    
    These thresholds prevent "semantic minimalism" attacks where agents
    provide technically valid but uninformative evidence.
    """
    # Minimum lengths (characters)
    min_description_length: int = 100
    min_reversibility_plan_length: int = 50
    min_alternative_description_length: int = 30
    min_reasoning_length: int = 50
    
    # Minimum entropy (bits per character, typical English ~4.0-4.5)
    min_description_entropy: float = 3.0
    
    # Repetition limits
    max_repetition_ratio: float = 0.3  # Max fraction of repeated words
    max_consecutive_repeated_chars: int = 5
    
    # Required fields that must be non-empty
    required_nonempty_fields: List[str] = None
    
    # Tier-specific overrides
    t2_min_description_length: int = 200
    t3_min_description_length: int = 500
    t3_min_alternatives: int = 2
    t3_min_reversibility_plan_length: int = 100
    
    def __post_init__(self):
        if self.required_nonempty_fields is None:
            self.required_nonempty_fields = [
                "description",
                "action_id",
            ]
    
    @classmethod
    def strict(cls) -> "EvidenceQualityPolicy":
        """Create a strict policy for production."""
        return cls(
            min_description_length=200,
            min_reversibility_plan_length=100,
            min_alternative_description_length=50,
            min_description_entropy=3.5,
            max_repetition_ratio=0.2,
            t2_min_description_length=300,
            t3_min_description_length=750,
            t3_min_alternatives=3,
            t3_min_reversibility_plan_length=200,
        )
    
    @classmethod
    def relaxed(cls) -> "EvidenceQualityPolicy":
        """Create a relaxed policy for development."""
        return cls(
            min_description_length=20,
            min_reversibility_plan_length=10,
            min_alternative_description_length=10,
            min_description_entropy=2.0,
            max_repetition_ratio=0.5,
            t2_min_description_length=50,
            t3_min_description_length=100,
            t3_min_alternatives=1,
            t3_min_reversibility_plan_length=20,
        )


def compute_entropy(text: str) -> float:
    """
    Compute Shannon entropy of text (bits per character).
    
    Higher entropy = more information density.
    Random text: ~8 bits/char
    Typical English: ~4.0-4.5 bits/char
    Repetitive text: ~1-2 bits/char
    """
    if not text:
        return 0.0
    
    # Count character frequencies
    freq = Counter(text.lower())
    total = len(text)
    
    # Compute entropy
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    
    return entropy


def compute_word_entropy(text: str) -> float:
    """
    Compute Shannon entropy at word level.
    
    This catches semantic repetition that character entropy misses.
    """
    words = re.findall(r'\b\w+\b', text.lower())
    if not words:
        return 0.0
    
    freq = Counter(words)
    total = len(words)
    
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    
    return entropy


def compute_repetition_ratio(text: str) -> float:
    """
    Compute ratio of repeated words to total words.
    
    High ratio indicates copy-paste or template content.
    """
    words = re.findall(r'\b\w+\b', text.lower())
    if not words:
        return 0.0
    
    freq = Counter(words)
    repeated = sum(count - 1 for count in freq.values() if count > 1)
    
    return repeated / len(words)


def find_consecutive_repeats(text: str) -> int:
    """
    Find longest run of consecutive repeated NON-WHITESPACE characters.
    
    Catches filler like "aaaaaaa" or "........" but ignores indentation
    and normal line breaks in multi-line strings.
    
    HARDENING (v2.0.1): Ignores whitespace runs to prevent false positives
    on properly formatted multi-line descriptions.
    """
    if not text:
        return 0
    
    # Normalize whitespace to single spaces to avoid false positives
    # on indentation in triple-quoted strings
    normalized = re.sub(r'\s+', ' ', text.strip())
    
    max_run = 1
    current_run = 1
    
    for i in range(1, len(normalized)):
        char = normalized[i]
        prev_char = normalized[i-1]
        
        # Skip whitespace in run counting
        if char.isspace() or prev_char.isspace():
            current_run = 1
            continue
            
        if char == prev_char:
            current_run += 1
            max_run = max(max_run, current_run)
        else:
            current_run = 1
    
    return max_run


def check_placeholder_patterns(text: str) -> List[str]:
    """
    Check for common placeholder patterns that indicate template content.
    """
    patterns = [
        (r'\[.*?\]', "Contains placeholder brackets [...]"),
        # Curly braces are common in code snippets; only treat as placeholder if it looks like a template token
        # (e.g., "{...}", "{INSERT_HERE}", "{placeholder}") rather than arbitrary punctuation.
        (r'\{\s*(?:\.\.\.|[^}]*[A-Za-z][^}]*)\s*\}', "Contains placeholder braces {...}"),
        (r'<.*?>', "Contains placeholder angle brackets <...>"),
        (r'TODO', "Contains TODO marker"),
        (r'FIXME', "Contains FIXME marker"),
        (r'XXX', "Contains XXX placeholder"),
        (r'lorem ipsum', "Contains lorem ipsum placeholder"),
        (r'example\.com', "Contains example.com placeholder"),
        (r'foo|bar|baz', "Contains foo/bar/baz placeholder"),
        (r'test_?action', "Contains test action placeholder"),
    ]
    
    issues = []
    text_lower = text.lower()
    
    for pattern, message in patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            issues.append(message)
    
    return issues


class EvidenceQualityChecker:
    """
    Checks evidence quality against minimum information density requirements.
    
    This prevents "semantic minimalism" attacks where agents provide
    technically valid but uninformative evidence.
    """
    
    def __init__(self, policy: Optional[EvidenceQualityPolicy] = None):
        self.policy = policy or EvidenceQualityPolicy()
    
    def check_evidence(
        self,
        evidence: Dict[str, Any],
        tier: str = "T1_SENSITIVE",
    ) -> Tuple[bool, List[str]]:
        """
        Check evidence quality.
        
        Returns (passed, issues).
        """
        issues = []
        
        # Get tier-adjusted thresholds
        if tier in ("T3_CATASTROPHIC",):
            min_desc_len = self.policy.t3_min_description_length
            min_rev_plan_len = self.policy.t3_min_reversibility_plan_length
            min_alts = self.policy.t3_min_alternatives
        elif tier in ("T2_HIGH_STAKES",):
            min_desc_len = self.policy.t2_min_description_length
            min_rev_plan_len = self.policy.min_reversibility_plan_length
            min_alts = 1
        else:
            min_desc_len = self.policy.min_description_length
            min_rev_plan_len = self.policy.min_reversibility_plan_length
            min_alts = 0
        
        # Check description
        description = evidence.get("description", "")
        if not isinstance(description, str):
            issues.append("INVALID_FIELD_TYPE: description must be string")
            description = ""
        issues.extend(self._check_text_quality(
            description, "description", min_desc_len
        ))

        # Check reversibility plan
        irr = evidence.get("irreversibility", {})
        if not isinstance(irr, dict):
            issues.append("INVALID_FIELD_TYPE: irreversibility must be object")
            irr = {}
        rev_plan = irr.get("reversibility_plan", "")
        if not isinstance(rev_plan, str):
            issues.append("INVALID_FIELD_TYPE: irreversibility.reversibility_plan must be string")
            rev_plan = ""
        if tier in ("T2_HIGH_STAKES", "T3_CATASTROPHIC"):
            issues.extend(self._check_text_quality(
                rev_plan, "reversibility_plan", min_rev_plan_len
            ))

        # Check alternatives
        alternatives = evidence.get("alternatives", [])
        if alternatives is None:
            alternatives = []
        if not isinstance(alternatives, list):
            issues.append("INVALID_FIELD_TYPE: alternatives must be list")
            alternatives = []
        if len(alternatives) < min_alts:
            issues.append(
                f"INSUFFICIENT_ALTERNATIVES: {len(alternatives)} provided, "
                f"minimum {min_alts} required for {tier}"
            )
        
        for i, alt in enumerate(alternatives):
            if not isinstance(alt, dict):
                issues.append(f"INVALID_FIELD_TYPE: alternative[{i}] must be object")
                alt_desc = ""
            else:
                alt_desc = alt.get("description", "")
            if not isinstance(alt_desc, str):
                issues.append(f"INVALID_FIELD_TYPE: alternative[{i}].description must be string")
                alt_desc = ""
            alt_issues = self._check_text_quality(
                alt_desc, f"alternative[{i}].description",
                self.policy.min_alternative_description_length
            )
            issues.extend(alt_issues)
        
        # Check required non-empty fields
        for field in self.policy.required_nonempty_fields:
            value = evidence.get(field, "")
            if value is None or (isinstance(value, str) and not value.strip()):
                issues.append(f"MISSING_REQUIRED_FIELD: {field}")
                continue
            if not isinstance(value, str):
                issues.append(f"INVALID_FIELD_TYPE: {field} must be string")
        
        # Check for placeholder patterns
        placeholder_issues = check_placeholder_patterns(description)
        if placeholder_issues:
            issues.extend([f"PLACEHOLDER_DETECTED: {issue}" for issue in placeholder_issues])
        
        return len(issues) == 0, issues

    def check_evidence_detailed(
        self,
        evidence: Dict[str, Any],
        tier: str = "T1_SENSITIVE",
    ) -> Tuple[bool, List[str], bool]:
        """Check evidence quality with reviewer-override semantics.

        Returns (quality_ok, issues, requires_reviewer_override).

        - quality_ok=False means **fatal** evidence defects (missing required fields, empty fields)
          and the action must be denied.
        - requires_reviewer_override=True means the evidence is structurally valid but fails
          "semantic minimalism" / MID checks (entropy/length/repetition/placeholders/etc.).
          For high-stakes tiers, callers may require a human-held reviewer key to proceed.

        NOTE: This function does not enforce tier policy; it only classifies issues.
        """
        passed, issues = self.check_evidence(evidence, tier)
        if passed:
            return True, [], False

        fatal_prefixes = (
            "MISSING_REQUIRED_FIELD:",
            "EMPTY_FIELD:",
            "INVALID_FIELD_TYPE:",
        )
        fatal = [i for i in issues if i.startswith(fatal_prefixes)]
        override = [i for i in issues if not i.startswith(fatal_prefixes)]

        # If any fatal issues exist, deny regardless of reviewer override.
        if fatal:
            return False, fatal + override, False

        # Otherwise, the evidence is structurally present but low-quality.
        return True, override, True
    
    def _check_text_quality(
        self,
        text: str,
        field_name: str,
        min_length: int,
    ) -> List[str]:
        """Check quality of a text field."""
        issues = []
        
        if not text:
            issues.append(f"EMPTY_FIELD: {field_name} is empty")
            return issues
        
        text = text.strip()
        
        # Length check
        if len(text) < min_length:
            issues.append(
                f"INSUFFICIENT_LENGTH: {field_name} is {len(text)} chars, "
                f"minimum {min_length} required"
            )
        
        # Entropy check
        entropy = compute_entropy(text)
        if entropy < self.policy.min_description_entropy:
            issues.append(
                f"LOW_ENTROPY: {field_name} entropy is {entropy:.2f} bits/char, "
                f"minimum {self.policy.min_description_entropy} required"
            )
        
        # Repetition check
        rep_ratio = compute_repetition_ratio(text)
        if rep_ratio > self.policy.max_repetition_ratio:
            issues.append(
                f"HIGH_REPETITION: {field_name} has {rep_ratio:.0%} repeated words, "
                f"maximum {self.policy.max_repetition_ratio:.0%} allowed"
            )
        
        # Consecutive character check
        consec = find_consecutive_repeats(text)
        if consec > self.policy.max_consecutive_repeated_chars:
            issues.append(
                f"FILLER_DETECTED: {field_name} has {consec} consecutive repeated chars, "
                f"maximum {self.policy.max_consecutive_repeated_chars} allowed"
            )
        
        return issues


def validate_evidence_quality(
    evidence: Dict[str, Any],
    tier: str = "T1_SENSITIVE",
    policy: Optional[EvidenceQualityPolicy] = None,
) -> Tuple[bool, List[str]]:
    """
    Validate evidence quality.
    
    Convenience function for one-off validation.
    
    Returns (passed, issues).
    """
    checker = EvidenceQualityChecker(policy)
    return checker.check_evidence(evidence, tier)


# Example usage and testing
if __name__ == "__main__":
    # Test with good evidence
    good_evidence = {
        "action_id": "DEPLOY_PROD_001",
        "description": """
            Deploy the new authentication service to production environment.
            This service handles user login, session management, and OAuth integration.
            The deployment will affect all users of the main application.
            Expected downtime: 5 minutes during the rolling update.
            Rollback plan: Revert to previous container image tag v2.3.1.
        """,
        "irreversibility": {
            "reversibility_plan": """
                Immediate rollback by reverting Kubernetes deployment to previous image.
                Database migrations are backward-compatible and do not require rollback.
                If issues persist, restore from hourly backup (RTO: 15 minutes).
            """
        },
        "alternatives": [
            {"description": "Delay deployment to next maintenance window (Sunday 2am UTC)"},
            {"description": "Deploy to staging first and monitor for 24 hours before production"},
        ]
    }
    
    passed, issues = validate_evidence_quality(good_evidence, "T2_HIGH_STAKES")
    print(f"Good evidence: passed={passed}")
    if issues:
        print("  Issues:", issues)
    
    # Test with bad evidence
    bad_evidence = {
        "action_id": "X",
        "description": "Do thing",
        "irreversibility": {
            "reversibility_plan": "."
        },
        "alternatives": []
    }
    
    passed, issues = validate_evidence_quality(bad_evidence, "T2_HIGH_STAKES")
    print(f"\nBad evidence: passed={passed}")
    print("  Issues:")
    for issue in issues:
        print(f"    - {issue}")
