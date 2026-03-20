from dataclasses import dataclass


@dataclass
class DeviceContext:
    """
    Test-only domain device object.

    Sprint A4.1:
    - Shape-only expansion
    - NO enforcement logic here
    """

    device_id: str
    registered: bool
    state: str

    # Existing posture fields
    clone_confirmed: bool = False
    secure_boot: bool = True
    compromised: bool = False

    # New trust / posture fields (Sprint A4+)
    hardware_backed: bool = True
    attestation_verified: bool = True
    binding_valid: bool = True
    replay_detected: bool = False


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
    Test helper to build a domain device object.

    Sprint A4.1:
    - Accepts all posture attributes used by tests
    - No validation
    - No policy
    - No security logic
    """

    return DeviceContext(
        device_id=device_id,
        registered=registered,
        state=state,
        clone_confirmed=clone_confirmed,
        secure_boot=secure_boot,
        compromised=compromised,
        hardware_backed=hardware_backed,
        attestation_verified=attestation_verified,
        binding_valid=binding_valid,
        replay_detected=replay_detected,
    )
