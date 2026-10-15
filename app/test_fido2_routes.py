from fastapi.testclient import TestClient

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
