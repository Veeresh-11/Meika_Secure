from datetime import datetime
import pytest

from app.security.context import SecurityContext
from app.security.device_snapshot import DeviceSnapshot


def test_fake_allow_context():

    ctx = SecurityContext.fake_allow_context()

    assert ctx.authenticated is True
    assert ctx.device is None
    assert ctx.grant is None


def test_fake_deny_context():

    ctx = SecurityContext.fake_deny_context()

    assert ctx.authenticated is True
    assert ctx.device is None


def test_fake_device():

    ctx = SecurityContext.fake_device()

    assert ctx.device is not None
    assert ctx.device.registered is True
    assert ctx.device.secure_boot is True


def test_fake_device_revoked():

    ctx = SecurityContext.fake_device_revoked()

    assert ctx.device.state == "revoked"


def test_invalid_device_type_rejected():

    with pytest.raises(
        TypeError,
        match="device must be DeviceSnapshot",
    ):
        SecurityContext(
            request_id="1",
            principal_id="user",
            intent="authentication.attempt",
            authenticated=True,
            device_id="dev1",
            device=object(),
            risk_signals={},
            request_time=datetime.utcnow(),
            metadata={},
            grant=None,
        )


def test_to_dict_without_device_or_grant():

    ctx = SecurityContext.fake_allow_context()

    data = ctx.to_dict()

    assert data["device"] is None
    assert data["grant"] is None
    assert data["principal_id"] == "user"


def test_to_dict_with_device():

    ctx = SecurityContext.fake_device()

    data = ctx.to_dict()

    assert data["device"] is not None
    assert data["device"]["device_id"] == "test-device"


class FakeGrant:

    def to_dict(self):
        return {
            "grant_id": "g1",
        }


def test_to_dict_with_grant():

    ctx = SecurityContext.fake_allow_context()

    object.__setattr__(
        ctx,
        "grant",
        FakeGrant(),
    )

    data = ctx.to_dict()

    assert data["grant"]["grant_id"] == "g1"