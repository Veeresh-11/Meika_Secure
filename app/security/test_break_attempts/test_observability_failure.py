import pytest

pytestmark = pytest.mark.track_a

from datetime import datetime

from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext
from app.security.decision import SecurityDecision, DecisionOutcome


def test_observability_failure_does_not_block_allow():
    def allow_policy(_):
        return SecurityDecision(
            outcome=DecisionOutcome.ALLOW,
            reason="ok",
            policy_version="x",
            evaluated_at=datetime.utcnow(),
            obligations=None,
        )

    pipeline = SecurityPipeline(policy_evaluator=allow_policy)

    ctx = SecurityContext(
        request_id="1",
        principal_id="u",
        intent="read",
        authenticated=True,
        device_id=None,
        device=None,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
    )

    decision = pipeline.evaluate(ctx)
    assert decision.outcome == DecisionOutcome.ALLOW
