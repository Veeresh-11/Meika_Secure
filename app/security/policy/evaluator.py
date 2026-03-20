# app/security/policy/evaluator.py

"""
Policy Evaluator Facade

This module exists to provide a stable import surface for the kernel
and test suite. Actual policy logic lives in engine / evaluators.
"""

from datetime import datetime
from typing import Any

from app.security.decision import SecurityDecision, DecisionOutcome
from app.security.results import PolicyResult, ResultKind, DenyReason


class PolicyEvaluator:
    """
    Advisory-only policy evaluator.

    IMPORTANT:
    - Policies have confirms no authority
    - Kernel will adapt / reject invalid outputs
    """

    def evaluate(self, context: Any) -> PolicyResult:
        return PolicyResult(
            outcome=DecisionOutcome.DENY,
            policy_version="default",
            evaluated_at=datetime.utcnow(),
            kind=ResultKind.POLICY,
            reason=DenyReason.POLICY_DENY.value,
        )
