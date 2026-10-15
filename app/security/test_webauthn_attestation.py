import pytest

from app.security.webauthn.attestation import AttestationVerificationError, verify_attestation


@pytest.mark.parametrize(
    "payload",
    [
        {"challenge": "challenge123", "hardware_backed": True, "attestation_verified": True, "public_key": "fake"},
        {"challenge": "challenge123", "hardware_backed": False, "attestation_verified": True, "public_key": "fake"},
        {"challenge": "challenge123", "hardware_backed": True, "attestation_verified": False, "public_key": "fake"},
    ],
)
def test_client_asserted_attestation_flags_fail_closed(payload):
    with pytest.raises(AttestationVerificationError, match="Legacy attestation format is disabled"):
        verify_attestation(payload, "challenge123")
