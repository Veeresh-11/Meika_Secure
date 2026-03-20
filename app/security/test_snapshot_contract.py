# app/security/test_snapshot_contract.py

import pytest
pytestmark = pytest.mark.track_a
from datetime import datetime

from app.security.context import SecurityContext
from app.security.device_snapshot import DeviceSnapshot
from app.security.errors import SecurityPipelineError
from app.security.test_helpers.device_builder import build_device


def test_raw_device_is_rejected():
    """
    A raw / domain device object must NEVER be accepted by SecurityContext.
    Only DeviceSnapshot is allowed (Sprint A2 contract).
    """

    # Domain device (not a snapshot)
    device = build_device(
        device_id="x",
        registered=True,
        state="active",
        clone_confirmed=False,
        secure_boot=True,
        compromised=False,
    )

    with pytest.raises(TypeError, match="DeviceSnapshot"):
        SecurityContext(
            request_id="req-1",
            principal_id="user-1",
            intent="authentication.attempt",
            authenticated=True,
            device_id=device.device_id,
            device=device,  # ❌ raw device must be rejected
            risk_signals={},
            request_time=datetime.utcnow(),
            metadata={},
        )


def test_device_snapshot_is_accepted():
    """
    A DeviceSnapshot is the ONLY valid device representation
    allowed to enter the security pipeline.
    """

    snapshot = DeviceSnapshot(
        device_id="device-1",
        registered=True,
        compromised=False,
        clone_confirmed=False,
    )

    ctx = SecurityContext(
        request_id="req-2",
        principal_id="user-2",
        intent="authentication.attempt",
        authenticated=True,
        device_id=snapshot.device_id,
        device=snapshot,  # ✅ snapshot allowed
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
    )

    assert ctx.device == snapshot


def test_snapshot_is_immutable():
    """
    DeviceSnapshot must be immutable.
    Mutation attempts indicate a security violation.
    """

    snapshot = DeviceSnapshot(
        device_id="device-immutable",
        registered=True,
        compromised=False,
        clone_confirmed=False,
    )

    with pytest.raises(Exception):
        snapshot.compromised = True  # ❌ mutation must fail

def test_only_snapshot_crosses_boundary():
    device = build_device(
    device_id="x",
    registered=True,
    state="active",
    clone_confirmed=False,
    secure_boot=True,
    compromised=False,
)

    with pytest.raises(TypeError):
        SecurityContext(..., device=device)

