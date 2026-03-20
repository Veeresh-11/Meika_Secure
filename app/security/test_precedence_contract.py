import pytest
from datetime import datetime
pytestmark = pytest.mark.track_a
from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext
from app.security.device_snapshot import DeviceSnapshot
from app.security.errors import SecurityPipelineError
from app.security.results import DenyReason


def test_policy_never_runs_after_clone(mocker):
    """
    Sprint A2 precedence contract:

    - Clone detection is ABSOLUTE
    - Policy evaluator must NEVER be called
    """

    policy = mocker.Mock()
    pipeline = SecurityPipeline(policy_evaluator=policy)

    snapshot = DeviceSnapshot(
        device_id="device-x",
        registered=True,
        compromised=False,
        clone_confirmed=True,  # 🔥 hard stop
    )

    ctx = SecurityContext(
        request_id="req-1",
        principal_id="user-1",
        intent="test",
        authenticated=True,
        device_id="device-x",
        device=snapshot,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
    )

    with pytest.raises(SecurityPipelineError) as exc:
        pipeline.evaluate(ctx)

    # ✅ Policy was never invoked
    policy.assert_not_called()

    # ✅ Canonical deny reason
    assert exc.value.reason == DenyReason.DEVICE_CLONED
