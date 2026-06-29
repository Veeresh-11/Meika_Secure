
from app.security.federation.verifier import TokenVerificationError


from app.security.test_federation_verifier_branches import build_stack

from dataclasses import replace

from app.security.pipeline import SecureIDKernel
from app.security.federation.keys import SigningKeyRegistry
from app.security.federation.replay_store import (
    InMemoryReplayStore,
)

from app.security.federation.revocation_store import (
    InMemoryRevocationStore,
)
from unittest.mock import patch
from app.security.federation.verifier import TokenReplayVerifier
import pytest
import jwt

def test_missing_kid_header():

    kernel, registry, service, verifier, ctx = build_stack()

    key = registry.get_active()

    token = jwt.encode(
        {"foo": "bar"},
        key.private_key,
        algorithm="EdDSA",
        headers={},
    )

    with pytest.raises(TokenVerificationError, match="Missing kid"):
        verifier.verify(token, audience="client-1")
        
from unittest.mock import patch


def test_invalid_algorithm():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(ctx, audience="client-1")

    with patch(
        "jwt.get_unverified_header",
        return_value={"kid": "x", "alg": "RS256"},
    ):
        with pytest.raises(TokenVerificationError, match="Invalid algorithm"):
            verifier.verify(token, audience="client-1")
            
from unittest.mock import patch

def test_unknown_key():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(
        ctx,
        audience="client-1",
    )

    with patch(
        "jwt.get_unverified_header",
        return_value={
            "kid": "unknown",
            "alg": "EdDSA",
        },
    ):
        with patch.object(
            verifier.keys,
            "get",
            return_value=None,
        ):
            with pytest.raises(
                TokenVerificationError,
                match="Unknown key",
            ):
                verifier.verify(
                    token,
                    audience="client-1",
                )
            
from types import SimpleNamespace


def test_revoked_key():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(ctx, audience="client-1")

    revoked_key = SimpleNamespace(
        revoked=True,
        public_key="x",
    )

    with patch.object(
        verifier.keys,
        "get",
        return_value=revoked_key,
    ):
        with pytest.raises(TokenVerificationError, match="Key revoked"):
            verifier.verify(token, audience="client-1")
            
import time


def test_future_iat():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(ctx, audience="client-1")

    original_decode = jwt.decode

    def fake_decode(*args, **kwargs):
        claims = original_decode(*args, **kwargs)
        claims["iat"] = int(time.time()) + 600
        return claims

    with patch("jwt.decode", side_effect=fake_decode):
        with pytest.raises(
            TokenVerificationError,
            match="Token issued in future",
        ):
            verifier.verify(
                token,
                audience="client-1",
                context=ctx,
            )
def test_invalid_token_type():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(ctx, audience="client-1")

    original_decode = jwt.decode

    def fake_decode(*args, **kwargs):
        claims = original_decode(*args, **kwargs)
        claims["typ"] = "refresh"
        return claims

    with patch("jwt.decode", side_effect=fake_decode):
        with pytest.raises(
            TokenVerificationError,
            match="Invalid token type",
        ):
            verifier.verify(
                token,
                audience="client-1",
                context=ctx,
            )
def test_missing_context_for_device_verification():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(
        ctx,
        audience="client-1",
    )

    with pytest.raises(
        TokenVerificationError,
        match="Missing context for device verification",
    ):
        verifier.verify(
            token,
            audience="client-1",
            context=None,
        )
def test_device_mismatch():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(
        ctx,
        audience="client-1",
    )

    bad_ctx = replace(
        ctx,
        device_id="other-device",
    )

    with pytest.raises(
        TokenVerificationError,
        match="Device mismatch",
    ):
        verifier.verify(
            token,
            audience="client-1",
            context=bad_ctx,
        )
        
def test_kernel_version_mismatch():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(ctx, audience="client-1")

    original_decode = jwt.decode

    def fake_decode(*args, **kwargs):
        claims = original_decode(*args, **kwargs)
        claims["kernel_version"] = "broken"
        return claims

    with patch("jwt.decode", side_effect=fake_decode):
        with pytest.raises(
            TokenVerificationError,
            match="Kernel version mismatch",
        ):
            verifier.verify(
                token,
                audience="client-1",
                context=ctx,
            )
            
def test_build_hash_mismatch():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(ctx, audience="client-1")

    original_decode = jwt.decode

    def fake_decode(*args, **kwargs):
        claims = original_decode(*args, **kwargs)
        claims["build_hash"] = "bad"
        return claims

    with patch("jwt.decode", side_effect=fake_decode):
        with pytest.raises(
            TokenVerificationError,
            match="Build hash mismatch",
        ):
            verifier.verify(
                token,
                audience="client-1",
                context=ctx,
            )

def test_revoke_token_method():

    kernel, registry, service, verifier, ctx = build_stack()

    verifier.revoke_token(
        "abc",
        9999999999,
    )

    assert verifier.revocation_store.is_revoked("abc")
    
from app.security.runtime_state import KernelState

def test_safe_mode_rejected():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(
        ctx,
        audience="client-1",
    )

    kernel._state = KernelState.SAFE_MODE

    with pytest.raises(
        TokenVerificationError,
        match="SAFE_MODE",
    ):
        verifier.verify(
            token,
            audience="client-1",
            context=ctx,
        )
def test_token_revoked():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(
        ctx,
        audience="client-1",
    )

    claims = verifier.verify(
        token,
        audience="client-1",
        context=ctx,
    )

    verifier.revoke_token(
        claims["jti"],
        claims["exp"],
    )

    with pytest.raises(
        TokenVerificationError,
        match="Token revoked",
    ):
        with patch.object(
            verifier.replay_store,
            "check_and_store",
            return_value=None,
        ):
            verifier.verify(
                token,
                audience="client-1",
                context=ctx,
            )
        
def test_missing_evidence_hash():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(
        ctx,
        audience="client-1",
    )

    original_decode = jwt.decode

    def fake_decode(*args, **kwargs):
        claims = original_decode(*args, **kwargs)
        claims.pop("evidence_hash", None)
        return claims

    with patch(
        "jwt.decode",
        side_effect=fake_decode,
    ):
        with pytest.raises(
            TokenVerificationError,
            match="Missing evidence hash",
        ):
            verifier.verify(
                token,
                audience="client-1",
                context=ctx,
            )
            
def test_missing_jti():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(
        ctx,
        audience="client-1",
    )

    original_decode = jwt.decode

    def fake_decode(*args, **kwargs):
        claims = original_decode(*args, **kwargs)
        claims.pop("jti", None)
        return claims

    with patch(
        "jwt.decode",
        side_effect=fake_decode,
    ):
        with pytest.raises(
            TokenVerificationError,
            match="Missing jti or exp",
        ):
            verifier.verify(
                token,
                audience="client-1",
                context=ctx,
            )

from app.security.risk_engine import RiskLevel

def test_high_risk_blocked():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(
        ctx,
        audience="client-1",
    )

    with patch.object(
        verifier.risk_engine,
        "assess",
        return_value=RiskLevel.HIGH,
    ):
        with pytest.raises(
            TokenVerificationError,
            match="High risk",
        ):
            verifier.verify(
                token,
                audience="client-1",
                context=ctx,
            )
            
from app.security.risk_engine import RiskLevel

def test_low_risk_path():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(
        ctx,
        audience="client-1",
    )

    with patch.object(
        verifier.risk_engine,
        "assess",
        return_value=RiskLevel.LOW,
    ):
        claims = verifier.verify(
            token,
            audience="client-1",
            context=ctx,
        )

    assert claims["risk"] == "low"
    
def test_replay_attack_detected_branch():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(ctx, audience="client-1")

    with patch.object(
        verifier.replay_store,
        "check_and_store",
        side_effect=Exception("boom"),
    ):
        with pytest.raises(
            TokenVerificationError,
            match="Replay attack detected",
        ):
            verifier.verify(
                token,
                audience="client-1",
                context=ctx,
            )
            
def test_invalid_pq_signature():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(ctx, audience="client-1")

    with patch.object(
        verifier.pq,
        "verify",
        return_value=False,
    ):
        with pytest.raises(
            TokenVerificationError,
            match="PQ signature invalid",
        ):
            verifier.verify(
                token,
                audience="client-1",
                context=ctx,
            )
            
def test_no_pq_fields_branch():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(ctx, audience="client-1")

    original_decode = jwt.decode

    def fake_decode(*args, **kwargs):
        claims = original_decode(*args, **kwargs)
        claims.pop("pq_sig", None)
        claims.pop("binding_hash", None)
        return claims

    with patch(
        "jwt.decode",
        side_effect=fake_decode,
    ):
        claims = verifier.verify(
            token,
            audience="client-1",
            context=ctx,
        )

    assert claims is not None
    
from types import SimpleNamespace

def test_get_all_branch():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(ctx, audience="client-1")

    record = SimpleNamespace(
        record_hash="hash1",
        previous_hash=None,
    )

    verifier.kernel.evidence_store = SimpleNamespace(
        get_all=lambda: [record]
    )

    original_decode = jwt.decode

    def fake_decode(*args, **kwargs):
        claims = original_decode(*args, **kwargs)
        claims["evidence_hash"] = "hash1"
        return claims

    with patch(
        "jwt.decode",
        side_effect=fake_decode,
    ):
        verifier.verify(
            token,
            audience="client-1",
            context=ctx,
        )
        
def test_unsupported_evidence_store():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(ctx, audience="client-1")

    verifier.kernel.evidence_store = object()

    with pytest.raises(
        TokenVerificationError,
        match="Unsupported evidence store",
    ):
        verifier.verify(
            token,
            audience="client-1",
            context=ctx,
        )
        
def test_chain_broken():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(ctx, audience="client-1")

    r1 = SimpleNamespace(
        record_hash="a",
        previous_hash=None,
    )

    r2 = SimpleNamespace(
        record_hash="b",
        previous_hash="wrong",
    )

    verifier.kernel.evidence_store = SimpleNamespace(
        get_all=lambda: [r1, r2]
    )

    original_decode = jwt.decode

    def fake_decode(*args, **kwargs):
        claims = original_decode(*args, **kwargs)
        claims["evidence_hash"] = "a"
        return claims

    with patch(
        "jwt.decode",
        side_effect=fake_decode,
    ):
        with pytest.raises(
            TokenVerificationError,
            match="Chain broken",
        ):
            verifier.verify(
                token,
                audience="client-1",
                context=ctx,
            )
            
def test_context_none_register_device_skipped():

    kernel, registry, service, verifier, ctx = build_stack()

    token = service.issue_token(
        ctx,
        audience="client-1",
    )

    original_decode = jwt.decode

    def fake_decode(*args, **kwargs):
        claims = original_decode(*args, **kwargs)
        claims.pop("device_state_hash", None)
        return claims

    with patch(
        "jwt.decode",
        side_effect=fake_decode,
    ):
        verifier.verify(
            token,
            audience="client-1",
            context=None,
        )

import builtins

from app.security.federation.verifier import _get_jwt


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
            
import builtins

from app.security.federation.replay_store import (
    InMemoryReplayStore,
)


def test_replay_store_fallback():

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if (
            name
            == "app.security.federation.replay_store_redis"
        ):
            raise ImportError()
        return real_import(name, *args, **kwargs)

    kernel = SecureIDKernel()

    registry = SigningKeyRegistry()
    registry.generate_and_register()

    with patch(
        "builtins.__import__",
        side_effect=fake_import,
    ):
        verifier = TokenReplayVerifier(
            kernel,
            registry,
        )

    assert isinstance(
        verifier.replay_store,
        InMemoryReplayStore,
    )
    
import builtins

from app.security.federation.revocation_store import (
    InMemoryRevocationStore,
)


def test_revocation_store_fallback():

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if (
            name
            == "app.security.federation.revocation_store_redis"
        ):
            raise ImportError()
        return real_import(name, *args, **kwargs)

    kernel = SecureIDKernel()

    registry = SigningKeyRegistry()
    registry.generate_and_register()

    with patch(
        "builtins.__import__",
        side_effect=fake_import,
    ):
        verifier = TokenReplayVerifier(
            kernel,
            registry,
        )

    assert isinstance(
        verifier.revocation_store,
        InMemoryRevocationStore,
    )