import pytest

pytestmark = [
    pytest.mark.track_a,
    pytest.mark.track_b,
]

from datetime import datetime

from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext
from app.security.device_snapshot import DeviceSnapshot
from app.security.errors import SecurityPipelineError
from app.security.decision import SecurityDecision, DecisionOutcome


def test_deny_without_evidence_is_forbidden():
    def deny_policy(_):
        return SecurityDecision(
            outcome=DecisionOutcome.DENY,
            reason="test",
            policy_version="x",
            evaluated_at=datetime.utcnow(),
            obligations=None,
        )

    pipeline = SecurityPipeline(policy_evaluator=deny_policy)

    ctx = SecurityContext(
        request_id="1",
        principal_id="u",
        intent="auth",
        authenticated=True,
        device_id=None,
        device=None,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
    )

    with pytest.raises(SecurityPipelineError, match="evidence"):
        pipeline.evaluate(ctx)
