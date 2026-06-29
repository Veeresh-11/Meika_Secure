import pytest

from app.security.pipeline import SecureIDKernel
from app.security.federation.service import FederationService
from app.security.federation.verifier import TokenReplayVerifier
from app.security.federation.keys import SigningKeyRegistry


def _setup():
    kernel = SecureIDKernel()
    registry = SigningKeyRegistry()
    registry.generate_and_register()

    service = FederationService(kernel, registry)
    verifier = TokenReplayVerifier(kernel, registry)

    ctx = kernel._default_context()

    return service, verifier, ctx


def test_new_device_increases_risk():
    service, verifier, ctx = _setup()

    token = service.issue_token(ctx, "client-1")

    claims = verifier.verify(token, "client-1", ctx)

    # first login → new device → should not be high risk
    assert claims["risk"] in ["low", "medium"]
    
from types import SimpleNamespace

from app.security.risk_engine import (
    RiskEngine,
    RiskLevel,
)


def test_high_risk_new_device_and_missing_hash():

    engine = RiskEngine()

    ctx = SimpleNamespace(
        principal_id="user1",
        device_id="device-new",
    )

    claims = {}

    result = engine.assess(ctx, claims)

    assert result == RiskLevel.HIGH
    
from types import SimpleNamespace

from app.security.risk_engine import (
    RiskEngine,
    RiskLevel,
)


def test_low_risk_without_user_or_device():
    engine = RiskEngine()

    ctx = SimpleNamespace(
        principal_id=None,
        device_id=None,
    )

    result = engine.assess(
        ctx,
        {"device_state_hash": "abc"},
    )

    assert result == RiskLevel.LOW


def test_medium_risk_new_device():
    engine = RiskEngine()

    ctx = SimpleNamespace(
        principal_id="user1",
        device_id="new-device",
    )

    result = engine.assess(
        ctx,
        {"device_state_hash": "present"},
    )

    assert result == RiskLevel.MEDIUM


def test_register_device():
    engine = RiskEngine()

    ctx = SimpleNamespace(
        principal_id="user1",
        device_id="device1",
    )

    engine.register_device(ctx)

    assert "device1" in engine._known_devices["user1"]
    
from types import SimpleNamespace
from app.security.risk_engine import RiskEngine, RiskLevel


def test_known_device_low_risk():
    engine = RiskEngine()

    ctx = SimpleNamespace(
        principal_id="user1",
        device_id="device1",
    )

    # register first
    engine.register_device(ctx)

    result = engine.assess(
        ctx,
        {"device_state_hash": "present"},
    )

    assert result == RiskLevel.LOW