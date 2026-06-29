from datetime import datetime

from app.security.policy.adapter import PolicyDecisionAdapter
from app.security.results import PolicyResult, DenyReason
from app.security.decision import (
    SecurityDecision,
    SecurityDecisionFactory,
    DecisionOutcome,
)
from app.security.version import KERNEL_VERSION
from app.security.results import (
    PolicyResult,
    ResultKind,
    DenyReason,
)


def test_adapt_policy_result():

    result = PolicyResult(
        outcome=DecisionOutcome.ALLOW,
        policy_version="TEST_POLICY",
        evaluated_at=datetime.utcnow(),
        kind=ResultKind.POLICY,
        reason="allowed",
    )

    decision = PolicyDecisionAdapter.adapt(result)

    assert decision.outcome == DecisionOutcome.ALLOW
    assert decision.reason == "allowed"
    assert decision.policy_version == KERNEL_VERSION
    assert decision.obligations is None


def test_adapt_security_decision():

    original = SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.DENY,
        reason="deny",
        policy_version="OLD_VERSION",
        evaluated_at=datetime.utcnow(),
        obligations={"x": 1},
        evidence_hash="abc123",
    )

    decision = PolicyDecisionAdapter.adapt(original)

    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason == "deny"
    assert decision.policy_version == KERNEL_VERSION
    assert decision.obligations == {"x": 1}
    assert decision.evidence_hash == "abc123"


def test_adapt_unknown_type_fallback_deny():

    decision = PolicyDecisionAdapter.adapt(
        object()
    )

    assert decision.outcome == DecisionOutcome.DENY
    assert decision.reason == DenyReason.POLICY_DENY.value
    assert decision.policy_version == KERNEL_VERSION