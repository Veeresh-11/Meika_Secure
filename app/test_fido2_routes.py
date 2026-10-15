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
    paths = {route.path for route in app.routes}
    assert "/api/v1/fido2/registration/options" in paths
    assert "/api/v1/fido2/registration/verify" in paths
    assert "/api/v1/fido2/authentication/options" in paths
    assert "/api/v1/fido2/authentication/verify" in paths
