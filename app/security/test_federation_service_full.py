import builtins
import pytest

from unittest.mock import patch

from app.security.federation.service import _get_jwt

from app.security.pipeline import SecureIDKernel
from app.security.federation.keys import SigningKeyRegistry
from app.security.federation.service import FederationService
from dataclasses import replace

def build_stack():

    kernel = SecureIDKernel()

    registry = SigningKeyRegistry()
    registry.generate_and_register()

    service = FederationService(
        kernel,
        registry,
    )

    ctx = kernel._default_context()

    return (
        kernel,
        registry,
        service,
        ctx,
    )

def test_get_jwt_import_error():

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "jwt":
            raise ImportError()
        return real_import(name, *args, **kwargs)

    with patch(
        "builtins.__import__",
        side_effect=fake_import,
    ):
        with pytest.raises(
            RuntimeError,
            match="jwt is required",
        ):
            _get_jwt()
            
from app.security.runtime_state import KernelState


def test_safe_mode_rejected():

    kernel, registry, service, ctx = build_stack()

    kernel._state = KernelState.SAFE_MODE

    with pytest.raises(
        Exception,
        match="SAFE_MODE",
    ):
        service.issue_token(
            ctx,
            audience="client-1",
        )
        
from types import SimpleNamespace


def test_deny_decision_rejected():

    kernel, registry, service, ctx = build_stack()

    kernel.evaluate = lambda _: SimpleNamespace(
        outcome=SimpleNamespace(name="DENY"),
        evidence_hash="abc",
        policy_version="v1",
    )

    with pytest.raises(
        Exception,
        match="DENY",
    ):
        service.issue_token(
            ctx,
            audience="client-1",
        )
        
def test_missing_device_id_rejected():

    kernel, registry, service, ctx = build_stack()

    ctx = replace(
        ctx,
        device_id=None,
        principal_id="real-user",
    )

    with pytest.raises(
        Exception,
        match="Device ID",
    ):
        service.issue_token(
            ctx,
            audience="client-1",
        )
        
def test_missing_evidence_hash():

    kernel, registry, service, ctx = build_stack()

    kernel.evaluate = lambda _: SimpleNamespace(
        outcome=SimpleNamespace(name="ALLOW"),
        evidence_hash=None,
        policy_version="v1",
    )

    with pytest.raises(
        Exception,
        match="Evidence hash",
    ):
        service.issue_token(
            ctx,
            audience="client-1",
        )
        
from dataclasses import replace


def test_kernel_context_without_device_id_allowed():

    kernel, registry, service, ctx = build_stack()

    ctx = replace(
        ctx,
        device_id=None,
        principal_id="kernel",
    )

    token = service.issue_token(
        ctx,
        audience="client-1",
    )

    assert token is not None
    

def test_device_present_skips_zero_trust_branch():

    kernel, registry, service, ctx = build_stack()

    token = service.issue_token(
        ctx,
        audience="client-1",
    )

    assert token is not None
    
def test_device_id_present_path():

    kernel, registry, service, ctx = build_stack()

    ctx = replace(
        ctx,
        device_id="real-device",
    )

    token = service.issue_token(
        ctx,
        audience="client-1",
    )

    assert token