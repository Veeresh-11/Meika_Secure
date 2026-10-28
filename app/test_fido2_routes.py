from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.api import fido2 as fido2_api
from app.api.fido2 import _consume_challenge

from app.main import app


client = TestClient(app)


def test_legacy_mock_webauthn_endpoints_are_disabled():
    paths = (
        "/api/v1/auth/webauthn/register/start",
        "/api/v1/auth/webauthn/register/finish",
        "/api/v1/auth/webauthn/authenticate/start",
        "/api/v1/auth/webauthn/authenticate/finish",
    )
    for path in paths:
        response = client.post(path, json={})
        assert response.status_code == 410
        assert "fido2" in response.json()["error"].lower()


def test_standards_based_fido2_endpoints_are_registered():
    paths = set(app.openapi()["paths"])
    assert "/api/v1/fido2/registration/options" in paths
    assert "/api/v1/fido2/registration/verify" in paths
    assert "/api/v1/fido2/authentication/options" in paths
    assert "/api/v1/fido2/authentication/verify" in paths



def test_fido2_registration_requires_primary_authentication():
    response = client.post(
        "/api/v1/fido2/registration/options",
        json={"email": "user@example.com", "device_name": "laptop"},
    )
    assert response.status_code == 401
    assert "authorization" in response.json()["detail"].lower()


def test_fido2_registration_verification_requires_enrollment_token():
    response = client.post(
        "/api/v1/fido2/registration/verify",
        json={
            "email": "user@example.com",
            "challenge": "dGVzdC1jaGFsbGVuZ2UtYnl0ZXM",
            "credential": {"id": "fake", "type": "public-key", "response": {}},
        },
    )
    assert response.status_code == 401



def test_challenge_consume_is_part_of_caller_transaction():
    db = MagicMock()
    db.execute.return_value = SimpleNamespace(rowcount=1)
    challenge = SimpleNamespace(id="challenge-id")

    _consume_challenge(
        db,
        challenge,
        purpose="fido2-authenticate",
        user_id="user-id",
    )

    db.execute.assert_called_once()
    db.commit.assert_not_called()
    db.rollback.assert_not_called()


def test_challenge_consume_rejects_race_without_committing():
    db = MagicMock()
    db.execute.return_value = SimpleNamespace(rowcount=0)
    challenge = SimpleNamespace(id="challenge-id")

    with pytest.raises(HTTPException) as error:
        _consume_challenge(
            db,
            challenge,
            purpose="fido2-authenticate",
            user_id="user-id",
        )

    assert error.value.status_code == 400
    db.commit.assert_not_called()



def test_registration_failure_rolls_back_challenge_consumption(monkeypatch):
    user = SimpleNamespace(id=uuid4(), tenant_id=uuid4(), email="user@example.com")
    enrollment_jti = "enrollment-once"
    challenge = SimpleNamespace(
        id=uuid4(),
        user_id=user.id,
        purpose="fido2-register:" + enrollment_jti,
        challenge="dGVzdC1jaGFsbGVuZ2UtYnl0ZXM",
        used=False,
        expires_at=datetime.utcnow() + timedelta(minutes=5),
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = challenge
    db.execute.return_value.rowcount = 1

    monkeypatch.setattr(
        fido2_api,
        "verify_enrollment_token",
        lambda token: {"sub": str(user.id), "jti": enrollment_jti},
    )
    monkeypatch.setattr(
        fido2_api.AuthService,
        "get_user_by_email",
        lambda db, email: user,
    )
    monkeypatch.setattr(
        fido2_api,
        "verify_registration",
        lambda **kwargs: {
            "credential_id": "credential-id",
            "public_key": "cHVibGljLWtleQ",
            "sign_count": 0,
            "attestation_type": "none",
        },
    )
    monkeypatch.setattr(
        fido2_api.DeviceService,
        "register",
        MagicMock(side_effect=RuntimeError("simulated device insert failure")),
    )

    payload = fido2_api.RegistrationVerifyRequest(
        email="user@example.com",
        challenge=challenge.challenge,
        credential={"id": "credential-id", "type": "public-key", "response": {}},
        device_name="test device",
    )
    with pytest.raises(HTTPException) as error:
        fido2_api.registration_verify(
            payload,
            authorization="Bearer enrollment-token",
            db=db,
        )

    assert error.value.status_code == 500
    db.rollback.assert_called_once()
    db.commit.assert_not_called()
