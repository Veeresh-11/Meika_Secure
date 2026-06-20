import pytest

from app.security.webauthn.attestation import (
    verify_attestation,
    AttestationVerificationError,
)


def valid_attestation():
    return {
        "challenge": "challenge123",
        "hardware_backed": True,
        "attestation_verified": True,
        "public_key": "pubkey",
        "credential_id": "cred1",
        "type": "fido2",
    }


def test_verify_attestation_success():
    result = verify_attestation(
        valid_attestation(),
        "challenge123",
    )

    assert result["credential_id"] == "cred1"
    assert result["public_key"] == "pubkey"
    assert result["hardware_backed"] is True
    assert result["attestation_verified"] is True


def test_attestation_must_be_dict():
    with pytest.raises(AttestationVerificationError):
        verify_attestation(
            "not-a-dict",
            "challenge123",
        )


def test_missing_challenge():
    data = valid_attestation()
    del data["challenge"]

    with pytest.raises(
        AttestationVerificationError,
        match="Missing challenge",
    ):
        verify_attestation(data, "challenge123")


def test_challenge_mismatch():
    with pytest.raises(
        AttestationVerificationError,
        match="Challenge mismatch",
    ):
        verify_attestation(
            valid_attestation(),
            "different",
        )


def test_hardware_backed_required():
    data = valid_attestation()
    data["hardware_backed"] = False

    with pytest.raises(
        AttestationVerificationError,
        match="hardware-backed",
    ):
        verify_attestation(data, "challenge123")


def test_attestation_verified_required():
    data = valid_attestation()
    data["attestation_verified"] = False

    with pytest.raises(
        AttestationVerificationError,
        match="Attestation not verified",
    ):
        verify_attestation(data, "challenge123")


def test_missing_public_key():
    data = valid_attestation()
    del data["public_key"]

    with pytest.raises(
        AttestationVerificationError,
        match="Missing public key",
    ):
        verify_attestation(data, "challenge123")


def test_defaults_are_used():
    data = {
        "challenge": "challenge123",
        "hardware_backed": True,
        "attestation_verified": True,
        "public_key": "pk",
    }

    result = verify_attestation(
        data,
        "challenge123",
    )

    assert result["credential_id"] == "unknown"
    assert result["attestation_type"] == "unknown"