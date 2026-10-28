from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from app.api import auth as auth_api
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
        expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=5),
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



def test_authentication_failure_rolls_back_consumed_challenge(monkeypatch):
    user = SimpleNamespace(id=uuid4(), tenant_id=uuid4(), email="user@example.com")
    challenge = SimpleNamespace(
        id=uuid4(),
        user_id=user.id,
        purpose="fido2-authenticate",
        challenge="dGVzdC1jaGFsbGVuZ2UtYnl0ZXM",
        used=False,
        expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=5),
    )
    credential = SimpleNamespace(
        id=uuid4(),
        user_id=user.id,
        tenant_id=user.tenant_id,
        credential_id="Y3JlZGVudGlhbC1pZA",
        public_key="cHVibGljLWtleQ",
        sign_count=0,
        device_id=uuid4(),
        revoked=False,
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = challenge
    db.execute.return_value.rowcount = 1

    monkeypatch.setattr(
        fido2_api.AuthService,
        "get_user_by_email",
        lambda db, email: user,
    )
    monkeypatch.setattr(
        fido2_api.CredentialService,
        "get_webauthn_credential",
        lambda **kwargs: credential,
    )
    monkeypatch.setattr(
        fido2_api,
        "verify_authentication",
        lambda **kwargs: {
            "credential_id": b"credential-id",
            "new_sign_count": 1,
        },
    )
    monkeypatch.setattr(
        fido2_api.CredentialService,
        "update_sign_count",
        MagicMock(side_effect=RuntimeError("simulated credential update failure")),
    )

    payload = fido2_api.AuthenticationVerifyRequest(
        email="user@example.com",
        challenge=challenge.challenge,
        credential={
            "id": credential.credential_id,
            "type": "public-key",
            "response": {},
        },
    )
    with pytest.raises(HTTPException) as error:
        fido2_api.authentication_verify(payload, db=db)

    assert error.value.status_code == 401
    db.rollback.assert_called_once()
    db.commit.assert_not_called()



def test_registration_options_rejects_concurrent_enrollment_token_reuse(monkeypatch):
    user = SimpleNamespace(id=uuid4(), tenant_id=uuid4(), email="user@example.com")
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None

    monkeypatch.setattr(
        fido2_api,
        "verify_enrollment_token",
        lambda token: {"sub": str(user.id), "jti": "one-time-enrollment"},
    )
    monkeypatch.setattr(
        fido2_api.AuthService,
        "get_user_by_email",
        lambda db, email: user,
    )
    monkeypatch.setattr(
        fido2_api.ChallengeService,
        "create",
        MagicMock(side_effect=IntegrityError("INSERT", {}, Exception("unique violation"))),
    )

    payload = fido2_api.RegistrationOptionsRequest(
        email="user@example.com",
        device_name="test device",
    )
    with pytest.raises(HTTPException) as error:
        fido2_api.registration_options(
            payload,
            authorization="Bearer enrollment-token",
            db=db,
        )

    assert error.value.status_code == 401
    assert "already used" in error.value.detail.lower()
    db.rollback.assert_called_once()



def test_password_login_deny_rolls_back_and_ignores_client_device_signals(monkeypatch):
    user_id = uuid4()
    session = SimpleNamespace(
        id=uuid4(),
        user_id=user_id,
        expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=30),
    )
    db = MagicMock()
    captured = {}

    monkeypatch.setattr(
        auth_api.AuthService,
        "login_user",
        lambda **kwargs: session,
    )

    def deny_policy(context):
        captured["context"] = context
        return SimpleNamespace(outcome=SimpleNamespace(value="DENY"))

    monkeypatch.setattr(auth_api.pipeline, "evaluate", deny_policy)

    payload = auth_api.LoginRequest(
        email="user@example.com",
        password="a-long-test-password",
        device_id="attacker-controlled-device",
        device_signals={"secure_boot": True, "hardware_backed": True},
    )
    with pytest.raises(HTTPException) as error:
        auth_api.login(payload, db=db)

    assert error.value.status_code == 403
    snapshot = captured["context"].device
    assert snapshot.registered is False
    assert snapshot.hardware_backed is False
    assert snapshot.attestation_verified is False
    assert snapshot.binding_valid is False
    assert snapshot.secure_boot is False
    db.rollback.assert_called_once()
    db.commit.assert_not_called()



def test_password_login_commits_only_after_policy_allow(monkeypatch):
    user_id = uuid4()
    session = SimpleNamespace(
        id=uuid4(),
        user_id=user_id,
        expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=30),
    )
    db = MagicMock()
    captured = {}

    monkeypatch.setattr(
        auth_api.AuthService,
        "login_user",
        lambda **kwargs: session,
    )
    monkeypatch.setattr(
        auth_api,
        "issue_enrollment_token",
        lambda user_id: "limited-enrollment-token",
    )

    def allow_policy(context):
        captured["context"] = context
        return SimpleNamespace(outcome=SimpleNamespace(value="ALLOW"))

    monkeypatch.setattr(auth_api.pipeline, "evaluate", allow_policy)

    payload = auth_api.LoginRequest(
        email="user@example.com",
        password="a-long-test-password",
        device_id="unverified-device",
        device_signals={"secure_boot": True, "hardware_backed": True},
    )
    response = auth_api.login(payload, db=db)

    assert response["decision"] == "ALLOW"
    assert response["webauthn_enrollment_token"] == "limited-enrollment-token"
    assert captured["context"].device.registered is False
    assert captured["context"].device.hardware_backed is False
    assert captured["context"].device.secure_boot is False
    db.commit.assert_called_once()
    db.rollback.assert_not_called()



def test_enrollment_challenge_index_is_partial_and_unique():
    from app.db.webauthn_models import WebAuthnChallenge

    index = next(
        item
        for item in WebAuthnChallenge.__table__.indexes
        if item.name == "uq_webauthn_enrollment_purpose"
    )

    assert index.unique is True
    pg_predicate = str(index.dialect_options["postgresql"]["where"])
    sqlite_predicate = str(index.dialect_options["sqlite"]["where"])
    assert "fido2-register:%" in pg_predicate
    assert "fido2-register:%" in sqlite_predicate



def test_password_login_token_issue_failure_rolls_back_session(monkeypatch):
    session = SimpleNamespace(
        id=uuid4(),
        user_id=uuid4(),
        expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=30),
    )
    db = MagicMock()
    monkeypatch.setattr(auth_api.AuthService, "login_user", lambda **kwargs: session)
    monkeypatch.setattr(
        auth_api.pipeline,
        "evaluate",
        lambda context: SimpleNamespace(outcome=SimpleNamespace(value="ALLOW")),
    )
    monkeypatch.setattr(
        auth_api,
        "issue_enrollment_token",
        MagicMock(side_effect=RuntimeError("simulated token signing failure")),
    )

    payload = auth_api.LoginRequest(
        email="user@example.com",
        password="a-long-test-password",
        device_id="unverified-device",
        device_signals={},
    )
    with pytest.raises(HTTPException) as error:
        auth_api.login(payload, db=db)

    assert error.value.status_code == 500
    db.rollback.assert_called_once()
    db.commit.assert_not_called()
