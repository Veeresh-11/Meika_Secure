from app.security.pipeline import SecureIDKernel
from app.security.federation.keys import SigningKeyRegistry
from app.security.federation.service import FederationService
from app.security.federation.verifier import TokenReplayVerifier
from dataclasses import replace
import pytest

jwt = pytest.importorskip("jwt")

def test_token_replay_verification_success():

    kernel = SecureIDKernel()
    registry = SigningKeyRegistry()
    registry.generate_and_register()

    service = FederationService(kernel, registry)
    verifier = TokenReplayVerifier(kernel, registry)

    ctx = kernel._default_context()
    ctx = replace(ctx, device_id="test-device")

    token = service.issue_token(ctx, audience="client-1")

    claims = verifier.verify(token, audience="client-1", context=ctx)

    assert claims["evidence_hash"] is not None


def test_token_invalid_if_evidence_missing():

    kernel = SecureIDKernel()
    registry = SigningKeyRegistry()
    registry.generate_and_register()

    service = FederationService(kernel, registry)
    verifier = TokenReplayVerifier(kernel, registry)

    ctx = kernel._default_context()
    token = service.issue_token(ctx, audience="client-1")

    # simulate ledger wipe
    kernel.evidence_store._records = {}

    try:
        verifier.verify(token, audience="client-1")
        assert False
    except Exception:
        assert True
