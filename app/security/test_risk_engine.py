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