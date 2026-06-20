from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


# =========================================================
# WebAuthn Register Finish
# =========================================================

class TestWebAuthnRegisterFinish:

    def test_register_finish_success(self):
        response = client.post(
            "/api/v1/auth/webauthn/register/finish",
            json={
                "email": "user@example.com",
                "attestation": {
                    "challenge": "abc123",
                    "hardware_backed": True,
                    "attestation_verified": True,
                    "public_key": "public-key",
                    "type": "basic",
                    "credential_id": "cred-1",
                },
            },
        )

        assert response.status_code == 200

        data = response.json()

        assert data["status"] == "registered"
        assert data["credential_id"] == "cred-1"

    def test_register_finish_missing_public_key(self):
        response = client.post(
            "/api/v1/auth/webauthn/register/finish",
            json={
                "email": "user@example.com",
                "attestation": {
                    "challenge": "abc123",
                    "hardware_backed": True,
                    "attestation_verified": True,
                },
            },
        )

        assert response.status_code in (422, 500)

    def test_register_finish_hardware_not_backed(self):
        response = client.post(
            "/api/v1/auth/webauthn/register/finish",
            json={
                "email": "user@example.com",
                "attestation": {
                    "challenge": "abc123",
                    "hardware_backed": False,
                    "attestation_verified": True,
                    "public_key": "pk",
                },
            },
        )

        assert response.status_code == 422

    def test_register_finish_attestation_not_verified(self):
        response = client.post(
            "/api/v1/auth/webauthn/register/finish",
            json={
                "email": "user@example.com",
                "attestation": {
                    "challenge": "abc123",
                    "hardware_backed": True,
                    "attestation_verified": False,
                    "public_key": "pk",
                },
            },
        )

        assert response.status_code == 422


# =========================================================
# WebAuthn Authenticate Finish
# =========================================================

class TestWebAuthnAuthenticateFinish:

    def test_authenticate_finish_success(self):
        response = client.post(
            "/api/v1/auth/webauthn/authenticate/finish",
            json={
                "email": "user@example.com",
                "credential_id": "cred-1",
                "assertion": {
                "sign_count": 1,
                "id": "cred-1",
                "rawId": "cred-1",
                "type": "public-key",
                "response": {"response": {}}
                             }
           },
        )

        assert response.status_code == 200

        data = response.json()

        assert data["status"] == "authenticated"
        assert "grant_id" in data

    def test_authenticate_finish_clone_detection(self):
        response = client.post(
            "/api/v1/auth/webauthn/authenticate/finish",
            json={
                "email": "user@example.com",
                "credential_id": "cred-1",
                "assertion": {
                "sign_count": 0,
                "id": "cred-1",
                "rawId": "cred-1",
                "type": "public-key",
                "response": {"response": {} }
                }
            },
        )

        assert response.status_code == 401

    def test_authenticate_finish_missing_credential_id(self):
        response = client.post(
            "/api/v1/auth/webauthn/authenticate/finish",
            json={
                "email": "user@example.com",
                "assertion": {
                    "sign_count": 1,
                    "id": "cred-1",
                    "rawId": "cred-1",
                    "type": "public-key",
                    "response": {"response": {}}
         } 
       },
    )

        assert response.status_code == 422