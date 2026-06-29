from datetime import datetime

import pytest

from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext
from app.security.results import DenyReason
from app.security.errors import SecurityPipelineError
from app.security.decision import DecisionOutcome
from app.security.decision import SecurityDecisionFactory


def test_deny_without_evidence_rejected():

    pipeline = SecurityPipeline()

    pipeline.policy_evaluator = lambda ctx: SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.DENY,
        reason=DenyReason.POLICY_DENY,
        policy_version="v1",
        evaluated_at=ctx.request_time,
        obligations={},
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

    with pytest.raises(SecurityPipelineError):
        pipeline.evaluate(ctx)