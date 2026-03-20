from datetime import datetime
import pytest

from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext
from app.security.decision import SecurityDecision, DecisionOutcome
from app.security.governance.policy_revocation import PolicyRevocationRegistry


def test_revoked_policy_denied():

    registry = PolicyRevocationRegistry({"1.0.0"})

    pipeline = SecurityPipeline(
        policy_evaluator=lambda _ctx: SecurityDecision(
            outcome=DecisionOutcome.ALLOW,
            reason="ok",
            policy_version="1.0.0",
            evaluated_at=datetime.utcnow(),
        ),
        revocation_registry=registry,
    )

    ctx = SecurityContext(
        request_id="1",
        principal_id="u",
        intent="login",
        authenticated=True,
        device_id=None,
        device=None,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
        grant=None,
    )

    with pytest.raises(Exception):
        pipeline.evaluate(ctx)
