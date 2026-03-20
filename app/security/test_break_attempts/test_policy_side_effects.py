import pytest

pytestmark = pytest.mark.break_attempt

from datetime import datetime
from unittest.mock import Mock

from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext
from app.security.device_snapshot import DeviceSnapshot
from app.security.errors import SecurityPipelineError


def test_policy_is_never_invoked_after_clone():
    policy = Mock()
    policy.evaluate = Mock(return_value=None)

    pipeline = SecurityPipeline(policy_evaluator=policy)

    snapshot = DeviceSnapshot(
        device_id="x",
        registered=True,
        compromised=False,
        clone_confirmed=True,
    )

    ctx = SecurityContext(
        request_id="1",
        principal_id="u",
        intent="auth",
        authenticated=True,
        device_id="x",
        device=snapshot,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
    )

    with pytest.raises(SecurityPipelineError):
        pipeline.evaluate(ctx)

    policy.evaluate.assert_not_called()
