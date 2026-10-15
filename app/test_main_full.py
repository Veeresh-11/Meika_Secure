import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock
from types import SimpleNamespace
from fastapi.responses import JSONResponse

import app.main as main_module


client = TestClient(main_module.app)

@pytest.fixture(scope="module", autouse=True)
def manage_test_client_lifecycle():
    """Close the shared TestClient transport and its event loop after this module."""
    try:
        with client:
            yield
    finally:
        client.close()



def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "running"}


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_global_exception_handler():
    response = main_module.app.exception_handlers[Exception](
        None,
        Exception("boom"),
    )

    result = await response

    assert result.status_code == 400


async def test_ci_security_bypass_flag_does_not_bypass_security(monkeypatch):
    monkeypatch.setenv("CI_SECURITY_BYPASS", "1")

    request = SimpleNamespace(
        url=SimpleNamespace(path="/private"),
        method="GET",
        headers={},
        client=SimpleNamespace(host="127.0.0.1"),
    )

    async def call_next(_request):
        pytest.fail("Protected request without device identity must not reach the handler")

    result = await main_module.enforce_security(request, call_next)

    assert isinstance(result, JSONResponse)
    assert result.status_code == 401
    assert result.body == b'{"error":"Missing device identity"}'


async def test_webauthn_non_post_branch(monkeypatch):
    monkeypatch.delenv("CI_SECURITY_BYPASS", raising=False)

    request = AsyncMock()
    request.url.path = "/api/v1/auth/webauthn/register/start"
    request.method = "GET"

    async def call_next(req):
        return "webauthn"

    result = await main_module.enforce_security(request, call_next)

    assert result == "webauthn"


async def test_unsupported_method_branch(monkeypatch):
    monkeypatch.delenv("CI_SECURITY_BYPASS", raising=False)

    request = AsyncMock()
    request.url.path = "/private"
    request.method = "TRACE"

    async def call_next(req):
        return "unsupported"

    result = await main_module.enforce_security(request, call_next)

    assert result == "unsupported"


async def test_success_path(monkeypatch):
    monkeypatch.delenv("CI_SECURITY_BYPASS", raising=False)

    request = AsyncMock()
    request.url.path = "/secure"
    request.method = "GET"

    monkeypatch.setattr(
        main_module,
        "resolve_device_context",
        lambda r: {"device_id": "device-1"},
    )

    async def fake_security_middleware(**kwargs):
        return None

    monkeypatch.setattr(
        main_module,
        "security_middleware",
        fake_security_middleware,
    )

    async def call_next(req):
        return "success"

    result = await main_module.enforce_security(request, call_next)

    assert result == "success"
    

def test_resolve_device_context_real():
    request = AsyncMock()

    request.headers = {
        "X-Device-ID": "device123",
        "User-Agent": "pytest-agent",
    }

    request.client.host = "127.0.0.1"

    result = main_module.resolve_device_context(request)

    assert result["device_id"] == "device123"
    assert result["user_agent"] == "pytest-agent"
    assert result["ip_address"] == "127.0.0.1"


async def test_missing_device_identity(monkeypatch):
    monkeypatch.delenv("CI_SECURITY_BYPASS", raising=False)

    request = AsyncMock()
    request.url.path = "/secure"
    request.method = "GET"

    monkeypatch.setattr(
        main_module,
        "resolve_device_context",
        lambda r: {"device_id": "unknown"},
    )

    async def call_next(req):
        return "should_not_happen"

    response = await main_module.enforce_security(request, call_next)

    assert isinstance(response, JSONResponse)
    assert response.status_code == 401


async def test_security_middleware_exception(monkeypatch):
    monkeypatch.delenv("CI_SECURITY_BYPASS", raising=False)

    request = AsyncMock()
    request.url.path = "/secure"
    request.method = "GET"

    monkeypatch.setattr(
        main_module,
        "resolve_device_context",
        lambda r: {"device_id": "device123"},
    )

    async def failing_security_middleware(**kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        main_module,
        "security_middleware",
        failing_security_middleware,
    )

    async def call_next(req):
        return "never"

    response = await main_module.enforce_security(request, call_next)

    assert isinstance(response, JSONResponse)
    assert response.status_code == 403


async def test_webauthn_post_path(monkeypatch):
    monkeypatch.delenv("CI_SECURITY_BYPASS", raising=False)

    request = AsyncMock()
    request.url.path = "/api/v1/auth/webauthn/register/start"
    request.method = "POST"

    monkeypatch.setattr(
        main_module,
        "resolve_device_context",
        lambda r: {"device_id": "device123"},
    )

    async def fake_security_middleware(**kwargs):
        return None

    monkeypatch.setattr(
        main_module,
        "security_middleware",
        fake_security_middleware,
    )

    async def call_next(req):
        return "ok"

    result = await main_module.enforce_security(request, call_next)

    assert result == "ok"