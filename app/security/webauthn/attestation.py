"""Legacy attestation shim.

The previous implementation trusted client-provided booleans and is unsafe.
Production FIDO2 ceremonies must use app.security.webauthn.fido2.
"""
from __future__ import annotations


class AttestationVerificationError(ValueError):
    """Raised when attestation cannot be cryptographically verified."""


def verify_attestation(attestation: dict, expected_challenge: str) -> dict:
    """Reject the legacy pseudo-attestation format.

    Browser-supplied hardware_backed or attestation_verified flags are not
    evidence of authenticator trust. Use verify_registration with the complete
    PublicKeyCredential JSON response.
    """
    raise AttestationVerificationError(
        "Legacy attestation format is disabled; submit a standard WebAuthn credential"
    )
