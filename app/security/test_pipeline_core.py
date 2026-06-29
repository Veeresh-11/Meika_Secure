import pytest

from types import SimpleNamespace
from datetime import datetime

from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext
from app.security.errors import SecurityPipelineError


def valid_context():

    return SecurityContext(
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


def test_none_context():

    pipeline = SecurityPipeline()

    with pytest.raises(SecurityPipelineError):
        pipeline.evaluate(None)


def test_unauthenticated_context():

    pipeline = SecurityPipeline()

    ctx = valid_context()

    from dataclasses import replace

    ctx = replace(
        ctx,
        authenticated=False,
    )

    with pytest.raises(SecurityPipelineError):
        pipeline.evaluate(ctx)


from app.security.device_snapshot import DeviceSnapshot
from dataclasses import replace

def test_real_device_snapshot():

    pipeline = SecurityPipeline()

    ctx = valid_context()

    device = DeviceSnapshot(
        device_id="dev1",
        registered=True,
        state="active",
        compromised=False,
        clone_confirmed=False,
        hardware_backed=True,
        attestation_verified=True,
        binding_valid=True,
        replay_detected=False,
    )

    ctx = replace(
        ctx,
        device=device,
    )

    result = pipeline.evaluate(ctx)

    assert result is not None