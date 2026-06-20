# app/api/test_auth_webauthn.py

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


class TestWebAuthnRegisterStart:

    def test_register_start_success(self):
        response = client.post(
            "/api/v1/auth/webauthn/register/start",
            json={
                "email": "user@example.com",
                "device_name": "pytest-device",
            },
        )

        assert response.status_code == 200

        data = response.json()

        assert "challenge" in data
        assert "rp" in data
        assert "user" in data

    def test_register_start_requires_email(self):
        response = client.post(
            "/api/v1/auth/webauthn/register/start",
            json={
                "device_name": "pytest-device",
            },
        )

        assert response.status_code == 422

    def test_register_start_requires_device_name(self):
        response = client.post(
            "/api/v1/auth/webauthn/register/start",
            json={
                "email": "user@example.com",
            },
        )

        assert response.status_code == 422


class TestWebAuthnAuthenticateStart:

    def test_authenticate_start_success(self):
        response = client.post(
            "/api/v1/auth/webauthn/authenticate/start",
            json={
                "email": "user@example.com",
            },
        )

        assert response.status_code == 200

        data = response.json()

        assert "challenge" in data

    def test_authenticate_start_requires_email(self):
        response = client.post(
            "/api/v1/auth/webauthn/authenticate/start",
            json={},
        )

        assert response.status_code == 422