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


def test_token_revocation():
    service, verifier, ctx = _setup()

    token = service.issue_token(ctx, "client-1")

    claims = verifier.verify(token, "client-1", ctx)

    # revoke token
    verifier.revoke_token(claims["jti"], claims["exp"])

    # second use should fail
    with pytest.raises(Exception):
        verifier.verify(token, "client-1", ctx)