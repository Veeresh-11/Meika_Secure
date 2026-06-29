from datetime import datetime

from app.security.device.context import (
    DeviceIdentityContext,
    DevicePostureContext,
    DeviceContext,
)


def test_device_identity_context():

    ctx = DeviceIdentityContext(
        hardware_backed=True,
        attestation_verified=True,
        binding_valid=True,
        clone_confirmed=False,
        replay_detected=False,
        last_attested_at=datetime.utcnow(),
    )

    assert ctx.hardware_backed is True
    assert ctx.attestation_verified is True
    assert ctx.binding_valid is True


def test_device_posture_context():

    posture = DevicePostureContext(
        secure_boot=True,
        compromised=False,
    )

    assert posture.secure_boot is True
    assert posture.compromised is False


def test_device_context():

    identity = DeviceIdentityContext(
        hardware_backed=True,
        attestation_verified=True,
        binding_valid=True,
        clone_confirmed=False,
        replay_detected=False,
        last_attested_at=None,
    )

    posture = DevicePostureContext(
        secure_boot=True,
        compromised=False,
    )

    device = DeviceContext(
        device_id="dev1",
        registered=True,
        state="active",
        identity=identity,
        posture=posture,
    )

    assert device.device_id == "dev1"
    assert device.registered is True
    assert device.state == "active"