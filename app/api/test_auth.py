import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from types import SimpleNamespace

import app.api.auth as auth
from app.security.errors import SecurityPipelineError
from app.security.webauthn.attestation import (
    AttestationVerificationError,
)
from datetime import datetime
from unittest.mock import MagicMock
from app.security.webauthn.assertion import verify_assertion

# ---------------------------------------------------------
# Test App
# ---------------------------------------------------------

app = FastAPI()
app.include_router(auth.router)

client = TestClient(app)


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

class DummyDB:
    pass


@pytest.fixture(autouse=True)
def override_db():

    auth.router.dependency_overrides = {}

    app.dependency_overrides[auth.get_db] = lambda: DummyDB()

    yield

    app.dependency_overrides.clear()


# ---------------------------------------------------------
# Password Register
# ---------------------------------------------------------

def test_register_success(monkeypatch):

    user = SimpleNamespace(id=123)

    monkeypatch.setattr(
        auth.AuthService,
        "register_user",
        lambda **kwargs: user,
    )

    response = client.post(
        "/auth/register",
        json={
            "email": "user@example.com",
            "password": "verystrongpassword",
            "display_name": "Boss",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["user_id"] == "123"

    assert "deprecated" in body["warning"].lower()


def test_register_duplicate(monkeypatch):

    def boom(**kwargs):
        raise Exception()

    monkeypatch.setattr(
        auth.AuthService,
        "register_user",
        boom,
    )

    response = client.post(
        "/auth/register",
        json={
            "email": "user@example.com",
            "password": "verystrongpassword",
            "display_name": "Boss",
        },
    )

    assert response.status_code == 409

    assert response.json()["detail"] == "User already exists"


# ---------------------------------------------------------
# Password Login
# ---------------------------------------------------------

def test_login_success(monkeypatch):

    session = SimpleNamespace(
        id=999,
        user_id=111,
        expires_at="2099-01-01T00:00:00Z",
    )

    monkeypatch.setattr(
        auth.AuthService,
        "login_user",
        staticmethod(lambda db, email, password: session),
    )

    monkeypatch.setattr(
        auth.device_registry,
        "is_registered",
        lambda *args, **kwargs: True,
    )

    monkeypatch.setattr(
        auth.posture_evaluator,
        "evaluate",
        lambda *args, **kwargs: auth.DevicePostureContext(
            secure_boot=True,
            compromised=False,
        ),
    )

    decision = SimpleNamespace(
        outcome=SimpleNamespace(
            value="ALLOW",
        )
    )

    monkeypatch.setattr(
        auth.pipeline,
        "evaluate",
        lambda ctx: decision,
    )

    response = client.post(
        "/auth/login",
        json={
            "email": "user@example.com",
            "password": "verystrongpassword",
            "device_id": "device-1",
            "device_signals": {},
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["session_id"] == "999"
    assert body["decision"] == "ALLOW"


def test_login_invalid_credentials_exception(monkeypatch):

    def fail(db, email, password):
        raise Exception()

    monkeypatch.setattr(
        auth.AuthService,
        "login_user",
        staticmethod(fail),
    )

    response = client.post(
        "/auth/login",
        json={
            "email": "user@example.com",
            "password": "verystrongpassword",
            "device_id": "device-1",
            "device_signals": {},
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_login_none_session(monkeypatch):

    monkeypatch.setattr(
        auth.AuthService,
        "login_user",
        staticmethod(lambda db, email, password: None),
    )

    response = client.post(
        "/auth/login",
        json={
            "email": "user@example.com",
            "password": "verystrongpassword",
            "device_id": "device-1",
            "device_signals": {},
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"
    
# ---------------------------------------------------------
# Login Failure Branches
# ---------------------------------------------------------

def test_login_invalid_device_context(monkeypatch):

    session = SimpleNamespace(
        id=1,
        user_id=1,
        expires_at="2099-01-01T00:00:00Z",
    )

    monkeypatch.setattr(
        auth.AuthService,
        "login_user",
        staticmethod(lambda db, email, password: session),
    )

    monkeypatch.setattr(
        auth.device_registry,
        "is_registered",
        lambda *args, **kwargs: True,
    )

    def boom(*args, **kwargs):
        raise RuntimeError("bad posture")

    monkeypatch.setattr(
        auth.posture_evaluator,
        "evaluate",
        boom,
    )

    response = client.post(
        "/auth/login",
        json={
            "email": "user@example.com",
            "password": "verystrongpassword",
            "device_id": "device-1",
            "device_signals": {},
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid device context"


def test_login_security_pipeline_error(monkeypatch):

    session = SimpleNamespace(
        id=1,
        user_id=1,
        expires_at="2099-01-01T00:00:00Z",
    )

    monkeypatch.setattr(
        auth.AuthService,
        "login_user",
        staticmethod(lambda db, email, password: session),
    )

    monkeypatch.setattr(
        auth.device_registry,
        "is_registered",
        lambda *args, **kwargs: True,
    )

    monkeypatch.setattr(
        auth.posture_evaluator,
        "evaluate",
        lambda *args, **kwargs: auth.DevicePostureContext(
            secure_boot=True,
            compromised=False,
        ),
    )

    def fail(ctx):
     raise SecurityPipelineError("Denied")

    monkeypatch.setattr(
        auth.pipeline,
        "evaluate",
        fail,
    )

    response = client.post(
        "/auth/login",
        json={
            "email": "user@example.com",
            "password": "verystrongpassword",
            "device_id": "device-1",
            "device_signals": {},
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Security evaluation failed"


def test_login_security_generic_failure(monkeypatch):

    session = SimpleNamespace(
        id=1,
        user_id=1,
        expires_at="2099-01-01T00:00:00Z",
    )

    monkeypatch.setattr(
        auth.AuthService,
        "login_user",
        staticmethod(lambda db, email, password: session),
    )

    monkeypatch.setattr(
        auth.device_registry,
        "is_registered",
        lambda *args, **kwargs: True,
    )

    monkeypatch.setattr(
        auth.posture_evaluator,
        "evaluate",
        lambda *args, **kwargs: auth.DevicePostureContext(
            secure_boot=True,
            compromised=False,
        ),
    )

    monkeypatch.setattr(
        auth.pipeline,
        "evaluate",
        lambda ctx: (_ for _ in ()).throw(Exception("boom")),
    )

    response = client.post(
        "/auth/login",
        json={
            "email": "user@example.com",
            "password": "verystrongpassword",
            "device_id": "device-1",
            "device_signals": {},
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Security evaluation failed"
# ---------------------------------------------------------
# WebAuthn Register Start
# ---------------------------------------------------------

def test_webauthn_register_start_success(monkeypatch):

    user = SimpleNamespace(
        id=123,
        email="user@example.com",
    )

    challenge_record = SimpleNamespace(
        challenge="challenge123",
    )

    monkeypatch.setattr(
        auth.AuthService,
        "get_user_by_email",
        staticmethod(lambda db, email: user),
    )

    monkeypatch.setattr(
        auth.ChallengeService,
        "create",
        staticmethod(
            lambda **kwargs: challenge_record
        ),
    )

    response = client.post(
        "/auth/webauthn/register/start",
        json={
            "email": "user@example.com",
            "device_name": "Laptop",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["challenge"] == "challenge123"
    assert body["rp"]["name"] == "Meika Authenticator"
    assert body["user"]["name"] == "user@example.com"

def test_webauthn_register_start_failure(monkeypatch):

    user = SimpleNamespace(
        id=123,
        email="user@example.com",
    )

    monkeypatch.setattr(
        auth.AuthService,
        "get_user_by_email",
        staticmethod(lambda db, email: user),
    )

    def fail(**kwargs):
        raise RuntimeError("database failure")

    monkeypatch.setattr(
        auth.ChallengeService,
        "create",
        staticmethod(fail),
    )

    response = client.post(
        "/auth/webauthn/register/start",
        json={
            "email": "user@example.com",
            "device_name": "Laptop",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Registration failed"
# ---------------------------------------------------------
# WebAuthn Register Finish
# ---------------------------------------------------------

def test_webauthn_register_finish_success(monkeypatch):

    challenge = SimpleNamespace(
        user_id="user-123",
        challenge="challenge123",
        used=False,
    )

    monkeypatch.setattr(
        auth.ChallengeService,
        "get",
        staticmethod(lambda **kwargs: challenge),
    )

    monkeypatch.setattr(
        auth.ChallengeService,
        "validate",
        staticmethod(lambda challenge: None),
    )

    monkeypatch.setattr(
        auth.ChallengeService,
        "consume",
        staticmethod(lambda **kwargs: None),
    )

    #
    # Device
    #

    monkeypatch.setattr(
        auth.DeviceService,
        "get_by_identifier",
        staticmethod(lambda **kwargs: None),
    )

    device = SimpleNamespace(
        id="device-123",
    )

    monkeypatch.setattr(
        auth.DeviceService,
        "register",
        staticmethod(lambda **kwargs: device),
    )

    #
    # Credential
    #

    credential = SimpleNamespace(
        id="cred-123",
    )

    monkeypatch.setattr(
        auth.CredentialService,
        "create_webauthn_credential",
        staticmethod(lambda **kwargs: credential),
    )

    #
    # WebAuthn
    #

    monkeypatch.setattr(
        auth,
        "verify_attestation",
        lambda *args, **kwargs: {
            "credential_id": "cred-123",
        },
    )

    response = client.post(
        "/auth/webauthn/register/finish",
        json={
            "email": "user@example.com",
            "attestation": {
                "challenge": "challenge123",
                "hardware_backed": True,
                "attestation_verified": True,
                "public_key": "public-key",
                "type": "basic",
                "credential_id": "cred-123",
            },
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["status"] == "registered"
    assert body["credential_id"] == "cred-123"
    assert body["message"] == "WebAuthn credential successfully registered"
    
def test_webauthn_register_finish_attestation_failure(monkeypatch):

    challenge = SimpleNamespace(
        challenge="challenge123",
        used=False,
    )

    monkeypatch.setattr(
        auth.ChallengeService,
        "get",
        staticmethod(lambda **kwargs: challenge),
    )

    monkeypatch.setattr(
        auth.ChallengeService,
        "validate",
        staticmethod(lambda challenge: None),
    )

    monkeypatch.setattr(
        auth.ChallengeService,
        "consume",
        staticmethod(lambda **kwargs: None),
    )

    def fail(*args, **kwargs):
        raise AttestationVerificationError("Bad attestation")

    monkeypatch.setattr(
        auth,
        "verify_attestation",
        fail,
    )

    response = client.post(
        "/auth/webauthn/register/finish",
        json={
            "email": "user@example.com",
            "attestation": {
                "challenge": "challenge123",
                "hardware_backed": True,
                "attestation_verified": True,
                "public_key": "public-key",
                "type": "basic",
                "credential_id": "cred-123",
            },
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "Bad attestation"

def test_webauthn_register_finish_internal_error(monkeypatch):

    def fail(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(
    auth,
    "verify_attestation",
    fail,
)

    response = client.post(
        "/auth/webauthn/register/finish",
        json={
            "email": "user@example.com",
            "attestation": {
                "challenge": "challenge123",
                "hardware_backed": True,
                "attestation_verified": True,
                "public_key": "public-key",
                "type": "basic",
                "credential_id": "cred-123",
            },
        },
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "Internal server error"


# ---------------------------------------------------------
# WebAuthn Authenticate Start
# ---------------------------------------------------------

def test_webauthn_authenticate_start_success(monkeypatch):

    user = SimpleNamespace(
        id=123,
        email="user@example.com",
    )

    challenge_record = SimpleNamespace(
        challenge="challenge-auth",
    )

    monkeypatch.setattr(
        auth.AuthService,
        "get_user_by_email",
        staticmethod(lambda db, email: user),
    )

    monkeypatch.setattr(
        auth.ChallengeService,
        "create",
        staticmethod(
            lambda **kwargs: challenge_record
        ),
    )

    response = client.post(
        "/auth/webauthn/authenticate/start",
        json={
            "email": "user@example.com",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["challenge"] == "challenge-auth"
    assert body["rpId"] == "meika.example.com"
    assert body["timeout"] == 60000


def test_webauthn_authenticate_start_failure(monkeypatch):

    user = SimpleNamespace(
        id=123,
        email="user@example.com",
    )

    monkeypatch.setattr(
        auth.AuthService,
        "get_user_by_email",
        staticmethod(lambda db, email: user),
    )

    def fail(**kwargs):
        raise RuntimeError("database failure")

    monkeypatch.setattr(
        auth.ChallengeService,
        "create",
        staticmethod(fail),
    )

    response = client.post(
        "/auth/webauthn/authenticate/start",
        json={
            "email": "user@example.com",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Authentication failed"


# ---------------------------------------------------------
# WebAuthn Authenticate Finish
# ---------------------------------------------------------

def test_webauthn_authenticate_finish_success(monkeypatch):

    credential_record = SimpleNamespace(
        id="cred-123",
        credential_id="credential-123",
        device_id="device-123",
        public_key="public-key",
        sign_count=0,
        hardware_backed=True,
        attestation_verified=True,
        attestation_type="basic",
        created_at=datetime.utcnow(),
        last_used_at=datetime.utcnow(),
        revoked=False,
    )

    monkeypatch.setattr(
        auth.CredentialService,
        "get_webauthn_credential",
        staticmethod(lambda **kwargs: credential_record),
    )

    update_sign_count = MagicMock()

    monkeypatch.setattr(
        auth.CredentialService,
        "update_sign_count",
        update_sign_count,
    )

    touch_last_used = MagicMock()

    monkeypatch.setattr(
        auth.CredentialService,
        "touch_last_used",
        touch_last_used,
    )

    monkeypatch.setattr(
        auth,
        "verify_assertion",
        lambda *args, **kwargs: None,
    )

    user = SimpleNamespace(
        id="user-123",
    )

    monkeypatch.setattr(
        auth.AuthService,
        "get_user_by_email",
        staticmethod(lambda *args, **kwargs: user),
    )

    #
    # Session
    #

    session = SimpleNamespace(
        id="session-123",
    )

    monkeypatch.setattr(
        auth.SessionService,
        "create",
        staticmethod(lambda **kwargs: session),
    )

    #
    # Grant
    #

    grant = SimpleNamespace(
        id="grant-123",
        jwt_id="jwt-123",
    )

    grant_create = MagicMock(
        return_value=grant,
    )

    monkeypatch.setattr(
        auth.GrantService,
        "create",
        grant_create,
    )

    monkeypatch.setattr(
        auth.GrantService,
        "touch",
        staticmethod(lambda **kwargs: None),
    )

    #
    # Device
    #

    device = SimpleNamespace(
        id="device-123",
    )

    monkeypatch.setattr(
        auth.DeviceService,
        "get",
        staticmethod(lambda **kwargs: device),
    )

    monkeypatch.setattr(
        auth.DeviceService,
        "touch",
        staticmethod(lambda **kwargs: None),
    )

    #
    # JWT
    #

    issue_token = MagicMock(
        return_value="mock.jwt.token",
    )

    monkeypatch.setattr(
        auth.TokenService,
        "issue_access_token",
        issue_token,
    )

    response = client.post(
        "/auth/webauthn/authenticate/finish",
        json={
            "email": "user@example.com",
            "credential_id": "credential-123",
            "assertion": {
                "id": "credential-123",
                "rawId": "credential-123",
                "type": "public-key",
                "response": {
                    "response": {
                        "clientDataJSON": "",
                        "authenticatorData": "",
                        "signature": "",
                    }
                },
            },
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["status"] == "authenticated"
    assert body["grant_id"] == "grant-123"
    assert body["session_id"] == "session-123"
    assert body["access_token"] == "mock.jwt.token"
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 3600

    update_sign_count.assert_called_once()
    touch_last_used.assert_called_once()
    grant_create.assert_called_once()
    issue_token.assert_called_once()

    #
    # Verify GrantService.create()
    #

    grant_kwargs = grant_create.call_args.kwargs

    assert grant_kwargs["user_id"] == "user-123"
    assert grant_kwargs["session_id"] == "session-123"
    assert grant_kwargs["credential_id"] == "cred-123"
    assert grant_kwargs["device_id"] == "device-123"
    assert grant_kwargs["grant_type"] == "access"
    assert grant_kwargs["created_by"] == "webauthn"

    #
    # Verify TokenService.issue_access_token()
    #

    token_kwargs = issue_token.call_args.kwargs

    assert token_kwargs["grant"] is grant
    assert token_kwargs["device_public_key"] == b"public-key"
    
    
    
def test_webauthn_authenticate_finish_failure(monkeypatch):

    def fail(*args, **kwargs):
        raise RuntimeError("verification failed")

    monkeypatch.setattr(
    auth,
    "verify_assertion",
    fail,
)

    response = client.post(
    "/auth/webauthn/authenticate/finish",
    json={
        "email": "user@example.com",
        "credential_id": "credential-123",
        "assertion": {
            "id": "credential-123",
            "rawId": "credential-123",
            "type": "public-key",
            "response": {
                "response": {
                    "clientDataJSON": "",
                    "authenticatorData": "",
                    "signature": "",
                }
            },
        },
    },
)

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication failed"