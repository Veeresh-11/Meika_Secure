import pytest

jwt = pytest.importorskip("jwt")
from app.security.pipeline import SecureIDKernel
from app.security.federation.keys import SigningKeyRegistry
from app.security.federation.service import FederationService


def test_token_issued_on_allow():

    kernel = SecureIDKernel()
    registry = SigningKeyRegistry()
    registry.generate_and_register()

    service = FederationService(kernel, registry)

    ctx = kernel._default_context()

    token = service.issue_token(ctx, audience="test-client")

    assert token is not None


def test_token_signature_valid():

    kernel = SecureIDKernel()
    registry = SigningKeyRegistry()
    key = registry.generate_and_register()

    service = FederationService(kernel, registry)

    ctx = kernel._default_context()
    token = service.issue_token(ctx, audience="test-client")

    decoded = jwt.decode(
        token,
        key.public_key,
        algorithms=["EdDSA"],
        audience="test-client",
        options={"verify_exp": False},
    )

    assert decoded["kernel_version"] is not None
    assert decoded["evidence_hash"] is not None
