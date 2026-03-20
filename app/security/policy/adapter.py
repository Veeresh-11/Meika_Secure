# app/security/policy/adapter.py

from datetime import datetime
from app.security.decision import SecurityDecision, DecisionOutcome
from app.security.results import DenyReason
from app.security.results import PolicyResult


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
                policy_version=policy_result.policy_version,
                evaluated_at=policy_result.evaluated_at,
                obligations=None,
            )

        # -------------------------------------------------
        # Already a SecurityDecision
        # -------------------------------------------------
        if isinstance(policy_result, SecurityDecision):
            return policy_result

        # -------------------------------------------------
        # Fallback deny
        # -------------------------------------------------
        return SecurityDecision(
            outcome=DecisionOutcome.DENY,
            reason=DenyReason.POLICY_DENY.value,
            policy_version="unknown",
            evaluated_at=datetime.utcnow(),
            obligations=None,
        )
