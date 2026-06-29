import pytest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from app.security.middleware import security_middleware
from app.security.errors import SecurityError


from datetime import datetime

from app.security.device.context import (
    DeviceContext,
    DeviceIdentityContext,
    DevicePostureContext,
)


class FakeRequest:
    def __init__(self):
        self.method = "GET"

        self.url = SimpleNamespace(
            path="/secure"
        )

        self.client = SimpleNamespace(
            host="127.0.0.1"
        )

        self.headers = {
            "Authorization": "Bearer token123",
            "user-agent": "pytest",
        }

        self.state = SimpleNamespace()



def FakeDeviceContext():

    identity = DeviceIdentityContext(
        hardware_backed=True,
        attestation_verified=True,
        binding_valid=True,
        clone_confirmed=False,
        replay_detected=False,
        last_attested_at=datetime.utcnow(),
    )

    posture = DevicePostureContext(
        secure_boot=True,
        compromised=False,
    )

    return DeviceContext(
        device_id="device-1",
        registered=True,
        state="active",
        identity=identity,
        posture=posture,
    )
    
@pytest.mark.asyncio
async def test_missing_authorization():
    request = FakeRequest()
    request.headers = {}

    with pytest.raises(SecurityError):
        await security_middleware(
            request=request,
            pipeline=Mock(),
            get_device_context=lambda _: FakeDeviceContext(),
        )


@pytest.mark.asyncio
async def test_invalid_authorization_format():
    request = FakeRequest()
    request.headers["Authorization"] = "token"

    with pytest.raises(SecurityError):
        await security_middleware(
            request=request,
            pipeline=Mock(),
            get_device_context=lambda _: FakeDeviceContext(),
        )


@pytest.mark.asyncio
async def test_policy_deny():
    request = FakeRequest()

    pipeline = Mock()

    pipeline.evaluate.return_value = SimpleNamespace(
        outcome=SimpleNamespace(name="DENY"),
        reason="denied",
    )

    fake_ctx = Mock()

    with patch(
        "app.security.middleware.enforce_device_bound_token"
    ), patch(
        "app.security.middleware.SecurityContext",
        return_value=fake_ctx,
    ):
        with pytest.raises(SecurityError):
            await security_middleware(
                request=request,
                pipeline=pipeline,
                get_device_context=lambda _: FakeDeviceContext(),
            )


@pytest.mark.asyncio
async def test_policy_allow():
    request = FakeRequest()

    pipeline = Mock()

    pipeline.evaluate.return_value = SimpleNamespace(
        outcome=SimpleNamespace(name="ALLOW"),
        reason="allowed",
    )

    fake_ctx = Mock()

    with patch(
        "app.security.middleware.enforce_device_bound_token"
    ), patch(
        "app.security.middleware.SecurityContext",
        return_value=fake_ctx,
    ):
        result = await security_middleware(
            request=request,
            pipeline=pipeline,
            get_device_context=lambda _: FakeDeviceContext(),
        )

    assert result is fake_ctx
    assert request.state.security_context is fake_ctx


@pytest.mark.asyncio
async def test_request_without_client():
    request = FakeRequest()
    request.client = None

    pipeline = Mock()

    pipeline.evaluate.return_value = SimpleNamespace(
        outcome=SimpleNamespace(name="ALLOW"),
        reason="allowed",
    )

    fake_ctx = Mock()

    with patch(
        "app.security.middleware.enforce_device_bound_token"
    ), patch(
        "app.security.middleware.SecurityContext",
        return_value=fake_ctx,
    ):
        ctx = await security_middleware(
            request=request,
            pipeline=pipeline,
            get_device_context=lambda _: FakeDeviceContext(),
        )

    assert ctx is fake_ctx