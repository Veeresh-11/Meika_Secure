from dataclasses import replace

from app.security.pipeline import SecureIDKernel
from app.security.federation.keys import SigningKeyRegistry
from app.security.federation.service import FederationService
from app.security.federation.verifier import (
    TokenReplayVerifier,
    TokenVerificationError,
)
import pytest
from app.security.runtime_state import KernelState

def build_stack():
    kernel = SecureIDKernel()

    registry = SigningKeyRegistry()
    registry.generate_and_register()

    service = FederationService(kernel, registry)
    verifier = TokenReplayVerifier(kernel, registry)

    ctx = kernel._default_context()
    ctx = replace(ctx, device_id="device-1")

    return kernel, registry, service, verifier, ctx

def test_missing_evidence_hash():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(ctx, audience="client-1")

    kernel.evidence_store._records = {}

    with pytest.raises(TokenVerificationError):
        verifier.verify(
            token,
            audience="client-1",
            context=ctx,
        )
        
def test_replay_attack_detected():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(ctx, audience="client-1")

    verifier.verify(
        token,
        audience="client-1",
        context=ctx,
    )

    with pytest.raises(TokenVerificationError):
        verifier.verify(
            token,
            audience="client-1",
            context=ctx,
        )

def test_revoked_token():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(ctx, audience="client-1")

    claims = verifier.verify(
        token,
        audience="client-1",
        context=ctx,
    )

    verifier.revoke_token(
        claims["jti"],
        claims["exp"],
    )

    with pytest.raises(TokenVerificationError):
        verifier.verify(
            token,
            audience="client-1",
            context=ctx,
        )
        

def test_safe_mode_rejected():

    kernel, registry, service, verifier, ctx = build_stack()

    kernel._state = KernelState.SAFE_MODE

    with pytest.raises(
        Exception,
        match="SAFE_MODE",
    ):
        service.issue_token(
            ctx,
            audience="client-1",
        )