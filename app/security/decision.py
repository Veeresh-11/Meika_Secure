"""
TRACK_A_CORE — SecurityDecision
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any
from enum import Enum
from datetime import datetime


class DecisionOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    RESTRICT = "restrict"


@dataclass(frozen=True)
class SecurityDecision:
    """
    Immutable security decision value object.

    Direct construction is restricted.
    Use SecurityDecisionFactory._kernel_create().
    """

    outcome: DecisionOutcome
    reason: str
    policy_version: str
    evaluated_at: datetime
    obligations: Optional[Dict[str, Any]] = None
    evidence_hash: Optional[str] = None

    def __post_init__(self):
        import inspect

        stack = inspect.stack()

        allowed_markers = (
            "pipeline.py",
            "adapter.py",
            "test_",
            "decision.py",  # allow factory itself
        )

        allowed = any(
            any(marker in frame.filename for marker in allowed_markers)
            for frame in stack
        )

        if not allowed:
            raise RuntimeError(
                "SecurityDecision must be created by kernel factory"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "reason": self.reason,
            "policy_version": self.policy_version,
            "evaluated_at": self.evaluated_at.isoformat()
            if self.evaluated_at
            else None,
            "obligations": self.obligations,
            "evidence_hash": self.evidence_hash,
        }

    def to_deterministic_dict(self):
       return {
          "outcome": self.outcome.name,
          "reason": self.reason,
          "policy_version": self.policy_version,
          "obligations": self.obligations,
        }
# ---------------------------------------------------------
# KERNEL FACTORY (STAGE 1 – INTRODUCTION ONLY)
# ---------------------------------------------------------

class SecurityDecisionFactory:
    """
    Kernel-authoritative constructor.

    Future versions will restrict direct instantiation.
    """

    @staticmethod
    def _kernel_create(
        *,
        outcome: DecisionOutcome,
        reason: str,
        policy_version: str,
        evaluated_at: datetime,
        obligations: Optional[Dict[str, Any]] = None,
        evidence_hash: Optional[str] = None,
    ) -> SecurityDecision:
        return SecurityDecision(
            outcome=outcome,
            reason=reason,
            policy_version=policy_version,
            evaluated_at=evaluated_at,
            obligations=obligations,
            evidence_hash=evidence_hash,
        )
