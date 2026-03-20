import pytest
from app.security.bootstrap import build_pipeline
from app.security.test_helpers.device_builder import build_device
from app.security.test_helpers.device_snapshot_builder import snapshot_from_device
from app.security.context import SecurityContext
from datetime import datetime
import uuid


def build_bad_device_context():
    device_ctx = build_device(
        device_id="dev-1",
        registered=False,  # This triggers hard-stop
        state="active",
    )
    snapshot = snapshot_from_device(device_ctx)

    return SecurityContext(
        request_id=str(uuid.uuid4()),
        principal_id="user-1",
        intent="user.login",
        authenticated=True,
        device_id=snapshot.device_id,
        device=snapshot,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
    )


def test_policy_not_called_after_device_fail(mocker):
    pipeline = build_pipeline()

    mock = mocker.patch.object(pipeline, "policy_evaluator")

    with pytest.raises(Exception):
        pipeline.evaluate(build_bad_device_context())

    mock.assert_not_called()
