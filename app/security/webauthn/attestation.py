
"""
WebAuthn Attestation Verification

Current implementation is a deterministic validator used by tests
and API contract verification.

Future versions can replace this module with real FIDO2/WebAuthn
attestation verification without changing the API surface.
"""

from __future__ import annotations


class AttestationVerificationError(ValueError):
    """Raised when attestation validation fails."""


def verify_attestation(
    attestation: dict,
    expected_challenge: str,
) -> dict:
    """
    Verify WebAuthn attestation payload.

    Parameters
    ----------
    attestation:
        Attestation payload received from client.

    expected_challenge:
        Challenge generated during registration start.

    Returns
    -------
    dict
        Verified credential metadata.

    Raises
    ------
    AttestationVerificationError
        If attestation validation fails.
    """

    if not isinstance(attestation, dict):
        raise AttestationVerificationError(
            "Attestation must be an object"
        )

    challenge = attestation.get("challenge")

    if not challenge:
        raise AttestationVerificationError(
            "Missing challenge"
        )

    if challenge != expected_challenge:
        raise AttestationVerificationError(
            "Challenge mismatch"
        )

    if not attestation.get("hardware_backed"):
        raise AttestationVerificationError(
            "Key not hardware-backed"
        )

    if not attestation.get("attestation_verified"):
        raise AttestationVerificationError(
            "Attestation not verified"
        )

    public_key = attestation.get("public_key")

    if not public_key:
        raise AttestationVerificationError(
            "Missing public key"
        )

    return {
        "credential_id": attestation.get(
            "credential_id",
            "unknown",
        ),
        "public_key": public_key,
        "attestation_type": attestation.get(
            "type",
            "unknown",
        ),
        "hardware_backed": True,
        "attestation_verified": True,
    }

