"""Red-team checks for fail-closed middleware behavior on restricted paths."""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def manage_test_client_lifecycle():
    """Release the shared client transport and its event loop after the tests."""
    try:
        with client:
            yield
    finally:
        client.close()


def test_auth_bypass():
    response = client.get("/api/v1/protected")
    assert response.status_code in {401, 403}


def test_token_replay():
    headers = {"Authorization": "Bearer fake", "X-Device-ID": "fake-device"}
    first = client.get("/api/v1/protected", headers=headers)
    second = client.get("/api/v1/protected", headers=headers)
    assert first.status_code in {401, 403}
    assert second.status_code in {401, 403}


def test_privilege_escalation():
    response = client.get("/api/v1/admin", headers={"X-Role": "admin"})
    assert response.status_code in {401, 403}


def test_device_spoof():
    response = client.get(
        "/api/v1/protected",
        headers={"X-Device-ID": "fake", "User-Agent": "bot"},
    )
    assert response.status_code in {401, 403}


def test_header_injection():
    response = client.get(
        "/api/v1/protected", headers={"X-Device-ID": "a\nb"}
    )
    assert response.status_code in {400, 403}


def test_invalid_payload():
    response = client.post(
        "/api/v1/auth/login",
        content='{"username":',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code in {400, 422}
