# app/security/policy/adapter.py

from datetime import datetime

from app.security.decision import SecurityDecision, DecisionOutcome
from app.security.results import DenyReason, PolicyResult
from app.security.version import KERNEL_VERSION


class PolicyDecisionAdapter:

    @staticmethod
    def adapt(policy_result) -> SecurityDecision:
        # -------------------------------------------------
        # Handle PolicyResult properly
        # -------------------------------------------------
        if isinstance(policy_result, PolicyResult):
            return SecurityDecision(
                outcome=policy_result.outcome,
                reason=policy_result.reason,
                policy_version=KERNEL_VERSION,  # 🔥 enforce kernel version
                evaluated_at=policy_result.evaluated_at,
                obligations=None,
            )

        # -------------------------------------------------
        # Already a SecurityDecision
        # -------------------------------------------------
        if isinstance(policy_result, SecurityDecision):
            # 🔥 normalize version here too (important)
            return SecurityDecision(
                outcome=policy_result.outcome,
                reason=policy_result.reason,
                policy_version=KERNEL_VERSION,
                evaluated_at=policy_result.evaluated_at,
                obligations=policy_result.obligations,
                evidence_hash=getattr(policy_result, "evidence_hash", None),
            )

        # -------------------------------------------------
        # Fallback deny
        # -------------------------------------------------
        return SecurityDecision(
            outcome=DecisionOutcome.DENY,
            reason=DenyReason.POLICY_DENY.value,
            policy_version=KERNEL_VERSION,  # 🔥 no "unknown"
            evaluated_at=datetime.utcnow(),
            obligations=None,
        )