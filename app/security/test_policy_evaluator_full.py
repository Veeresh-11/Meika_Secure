# app/security/test_policy_evaluator_full.py

from app.security.policy.evaluator import PolicyEvaluator
from app.security.decision import DecisionOutcome
from app.security.results import (
    ResultKind,
    DenyReason,
)


def test_evaluate_returns_default_deny_policy_result():
    evaluator = PolicyEvaluator()

    result = evaluator.evaluate(object())

    assert result.outcome == DecisionOutcome.DENY
    assert result.policy_version == "default"
    assert result.kind == ResultKind.POLICY
    assert result.reason == DenyReason.POLICY_DENY.value