# app/security/test_helpers/device_snapshot_builder.py

from app.security.device_snapshot import DeviceSnapshot
from app.security.test_helpers.device_builder import DeviceContext


def snapshot_from_device(device: DeviceContext) -> DeviceSnapshot:
    """
    Sprint A4.2 adapter:
    Converts a mutable DeviceContext into an immutable DeviceSnapshot
    suitable for SecurityContext.

    IMPORTANT:
    This must be a LOSSLESS projection of all security-relevant fields.
    """

    return DeviceSnapshot(
        device_id=device.device_id,
        registered=device.registered,
        state=getattr(device, "state", None),
        hardware_backed=getattr(device, "hardware_backed", False),
        attestation_verified=getattr(device, "attestation_verified", False),
        binding_valid=getattr(device, "binding_valid", False),
        secure_boot=getattr(device, "secure_boot", False),
        replay_detected=getattr(device, "replay_detected", False),
        compromised=getattr(device, "compromised", False),
        clone_confirmed=getattr(device, "clone_confirmed", False),
    )
