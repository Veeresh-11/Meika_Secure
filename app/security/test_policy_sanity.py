import pytest

pytestmark = pytest.mark.track_a

from datetime import datetime

from app.security.bootstrap import build_pipeline
from app.security.context import SecurityContext
from app.security.device_snapshot import DeviceSnapshot
from app.security.test_helpers.device_builder import build_device


def test_policy_sanity():
    pipeline = build_pipeline()

    device = build_device(
        device_id="device-1",
        registered=True,
        state="active",
        secure_boot=True,
        compromised=False,
        clone_confirmed=False,
        hardware_backed=True,          # ✅ REQUIRED
        attestation_verified=True,     # ✅ REQUIRED
        binding_valid=True,            # ✅ REQUIRED
        replay_detected=False,         # ✅ REQUIRED
    )

    snapshot = DeviceSnapshot(
        device_id=device.device_id,
        registered=device.registered,
        compromised=device.posture.compromised,
        clone_confirmed=device.identity.clone_confirmed,
        state=device.state,
        hardware_backed=device.identity.hardware_backed,
        attestation_verified=device.identity.attestation_verified,
        binding_valid=device.identity.binding_valid,
        replay_detected=device.identity.replay_detected,
        secure_boot=device.posture.secure_boot,
    )

    ctx = SecurityContext(
        request_id="req-1",
        principal_id="user-1",
        intent="authentication.attempt",
        authenticated=True,
        device_id=device.device_id,
        device=snapshot,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={},
    )

    decision = pipeline.evaluate(ctx)

    assert decision is not None