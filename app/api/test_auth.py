import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from types import SimpleNamespace

import app.api.auth as auth
from app.security.errors import SecurityPipelineError
from app.security.webauthn.attestation import (
    AttestationVerificationError,
)
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

    print(response.status_code)
    print(response.json())

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
     print(type(SecurityPipelineError("Denied")))
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

    monkeypatch.setattr(
        "app.security.webauthn.challenge.generate_challenge",
        lambda: "challenge123",
    )

    response = client.post(
        "/auth/webauthn/register/start",
        json={
            "email": "user@example.com",
            "device_name": "Laptop",
        },
    )

    print(response.status_code)
    print(response.json())

    assert response.status_code == 200
    
    body = response.json()

    assert body["challenge"] == "challenge123"
    assert body["rp"]["name"] == "Meika Authenticator"
    assert body["user"]["name"] == "user@example.com"


def test_webauthn_register_start_failure(monkeypatch):

    def fail():
        raise Exception()

    monkeypatch.setattr(
    "app.security.webauthn.challenge.generate_challenge",
    fail,
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

    monkeypatch.setattr(
        "app.security.webauthn.attestation.verify_attestation",
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


def test_webauthn_register_finish_attestation_failure(monkeypatch):

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

    monkeypatch.setattr(
        "app.security.webauthn.challenge.generate_challenge",
        lambda: "challenge-auth",
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

    def fail():
        raise RuntimeError("boom")

    monkeypatch.setattr(
    "app.security.webauthn.challenge.generate_challenge",
    fail,
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

    monkeypatch.setattr(
        auth,
        "verify_assertion",
        lambda *args, **kwargs: None,
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
    assert body["grant_id"] == "grant-placeholder"
    assert body["access_token"] == "jwt-token-placeholder"
    assert body["token_type"] == "Bearer"


def test_webauthn_authenticate_finish_failure(monkeypatch):

    def fail(*args, **kwargs):
        raise RuntimeError("verification failed")

    monkeypatch.setattr(
    auth,
    "verify_attestation",
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