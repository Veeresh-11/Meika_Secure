import pytest
from datetime import datetime

from app.security.webauthn.assertion import verify_assertion
from app.security.webauthn.models import WebAuthnCredential


def make_credential():
    return WebAuthnCredential(
        credential_id=b"cred1",
        public_key=b"pubkey",
        sign_count=10,
        hardware_backed=True,
        attestation_verified=True,
        attestation_type="fido2",
        created_at=datetime.utcnow(),
        last_used_at=datetime.utcnow(),
        revoked=False,
    )


def test_verify_assertion_success():
    cred = make_credential()

    verify_assertion(
        {"sign_count": 11},
        cred,
    )

    assert cred.sign_count == 11
    assert cred.revoked is False
    assert cred.last_used_at is not None


def test_revoked_credential_rejected():
    cred = make_credential()
    cred.revoked = True

    with pytest.raises(
        ValueError,
        match="Credential revoked",
    ):
        verify_assertion(
            {"sign_count": 11},
            cred,
        )


def test_clone_detection_equal_counter():
    cred = make_credential()

    with pytest.raises(
        ValueError,
        match="Clone detected",
    ):
        verify_assertion(
            {"sign_count": 10},
            cred,
        )

    assert cred.revoked is True


def test_clone_detection_lower_counter():
    cred = make_credential()

    with pytest.raises(
        ValueError,
        match="Clone detected",
    ):
        verify_assertion(
            {"sign_count": 5},
            cred,
        )

    assert cred.revoked is True


def test_last_used_timestamp_updated():
    cred = make_credential()

    old_time = cred.last_used_at

    verify_assertion(
        {"sign_count": 15},
        cred,
    )

    assert cred.last_used_at >= old_time


def test_multiple_successive_assertions():
    cred = make_credential()

    verify_assertion(
        {"sign_count": 11},
        cred,
    )

    verify_assertion(
        {"sign_count": 12},
        cred,
    )

    verify_assertion(
        {"sign_count": 13},
        cred,
    )

    assert cred.sign_count == 13