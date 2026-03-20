from datetime import datetime
from app.security.device.context import DeviceIdentityContext


def build_device_identity_from_webauthn(
    *,
    hardware_backed: bool,
    attestation_verified: bool,
    binding_valid: bool,
    clone_confirmed: bool,
    replay_detected: bool,
    last_attested_at: datetime | None,
) -> DeviceIdentityContext:
    return DeviceIdentityContext(
        hardware_backed=hardware_backed,
        attestation_verified=attestation_verified,
        binding_valid=binding_valid,
        clone_confirmed=clone_confirmed,
        replay_detected=replay_detected,
        last_attested_at=last_attested_at,
    )
