from datetime import datetime

from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext
from app.security.decision import (
    SecurityDecisionFactory,
    DecisionOutcome,
)
from app.security.version import KERNEL_VERSION


def deny_policy(ctx):

    return SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.DENY,
        reason="DENY",
        policy_version=KERNEL_VERSION,
        evaluated_at=ctx.request_time,
        obligations={
            "evidence": {
                "reason": "DENY"
            }
        },
    )


def test_deny_normalization():

    pipeline = SecurityPipeline(
        policy_evaluator=deny_policy
    )

    ctx = SecurityContext(
        request_id="1",
        principal_id="user",
        intent="authentication.attempt",
        authenticated=True,
        device=None,
        device_id=None,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
        grant=None,
    )

    decision = pipeline.evaluate(ctx)

    assert decision.outcome.name == "DENY"
    assert "evidence" in decision.obligations