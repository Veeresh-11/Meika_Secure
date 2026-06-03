from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_auth_bypass():
    assert client.get("/api/v1/protected").status_code in [401, 403]


def test_token_replay():
    h = {"Authorization": "Bearer fake"}
    assert client.get("/api/v1/protected", headers=h).status_code in [401, 403]
    assert client.get("/api/v1/protected", headers=h).status_code in [401, 403]


def test_privilege_escalation():
    assert client.get("/api/v1/admin", headers={"X-Role": "admin"}).status_code in [401, 403]


def test_device_spoof():
    assert client.get(
        "/api/v1/protected",
        headers={"X-Device-ID": "fake", "User-Agent": "bot"},
    ).status_code in [401, 403]


def test_header_injection():
    assert client.get(
        "/api/v1/protected", headers={"X-Device-ID": "a\nb"}
    ).status_code in [400, 403]


def test_invalid_payload():
    response = client.post(
        "/api/v1/auth/login",
        content='{"username":',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code in [400, 422]