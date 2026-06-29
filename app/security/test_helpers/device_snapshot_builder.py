from datetime import datetime

from app.security.device.context import (
    DeviceContext,
    DeviceIdentityContext,
    DevicePostureContext,
)
from app.security.device_snapshot import DeviceSnapshot

def snapshot_from_device(device: DeviceContext) -> DeviceSnapshot:
    return DeviceSnapshot(
        
        device_id=device.device_id,
        registered=device.registered,
        state=device.state,

        hardware_backed=device.identity.hardware_backed,
        attestation_verified=device.identity.attestation_verified,
        binding_valid=device.identity.binding_valid,

        secure_boot=device.posture.secure_boot,
        compromised=device.posture.compromised,

        replay_detected=device.identity.replay_detected,
        clone_confirmed=device.identity.clone_confirmed,
       
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