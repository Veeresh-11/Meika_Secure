from datetime import datetime

from app.security.device.context import (
    DeviceContext,
    DeviceIdentityContext,
    DevicePostureContext,
)


def build_device(
    *,
    device_id: str,
    registered: bool,
    state: str,
    clone_confirmed: bool = False,
    secure_boot: bool = True,
    compromised: bool = False,
    hardware_backed: bool = True,
    attestation_verified: bool = True,
    binding_valid: bool = True,
    replay_detected: bool = False,
) -> DeviceContext:
    """
    Test helper to build a DeviceContext matching the production model.
    """

    identity = DeviceIdentityContext(
        hardware_backed=hardware_backed,
        attestation_verified=attestation_verified,
        binding_valid=binding_valid,
        clone_confirmed=clone_confirmed,
        replay_detected=replay_detected,
        last_attested_at=datetime.utcnow(),
    )

    posture = DevicePostureContext(
        secure_boot=secure_boot,
        compromised=compromised,
    )

    return DeviceContext(
        device_id=device_id,
        registered=registered,
        state=state,
        identity=identity,
        posture=posture,
    )