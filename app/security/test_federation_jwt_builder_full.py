from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

from app.security.federation.jwt_builder import (
    DeterministicJWTBuilder,
)
from app.security.federation.pq_signer import (
    PostQuantumSigner,
    SigningAlgorithm,
)


def test_build_with_private_key_path():

    signer = PostQuantumSigner()

    builder = DeterministicJWTBuilder(
        pq_signer=signer,
    )

    fake_key = SimpleNamespace(
        private_key="secret",
        kid="kid123",
    )

    with patch(
        "app.security.federation.jwt_builder.jwt.encode",
        return_value="jwt-token",
    ):
        token = builder.build(
            signing_key=fake_key,
            principal_id="user1",
            audience="api",
            evidence_hash="evidence",
            device_state_hash="device",
            policy_version="v1",
            issued_at=datetime.utcnow(),
        )

    assert token == "jwt-token"


def test_build_without_private_key_uses_pq_jwt():

    builder = DeterministicJWTBuilder()

    fake_key = object()

    token = builder.build(
        signing_key=fake_key,
        principal_id="user1",
        audience="api",
        evidence_hash="evidence",
        device_state_hash="device",
        policy_version="v1",
        issued_at=datetime.utcnow(),
    )

    assert "." in token


def test_build_falls_back_when_jwt_encode_fails():

    builder = DeterministicJWTBuilder()

    fake_key = SimpleNamespace(
        private_key="secret",
        kid="kid123",
    )

    with patch(
        "app.security.federation.jwt_builder.jwt.encode",
        side_effect=Exception("boom"),
    ):
        token = builder.build(
            signing_key=fake_key,
            principal_id="user1",
            audience="api",
            evidence_hash="evidence",
            device_state_hash="device",
            policy_version="v1",
            issued_at=datetime.utcnow(),
        )

    assert "." in token


def test_build_generates_default_timestamp():

    builder = DeterministicJWTBuilder()

    token = builder.build(
        signing_key=object(),
        principal_id="user1",
        audience="api",
        evidence_hash="evidence",
        device_state_hash="device",
        policy_version="v1",
    )

    assert "." in token


def test_build_pq_jwt_rs256():

    builder = DeterministicJWTBuilder()

    token = builder._build_pq_jwt(
        {"sub": "user"},
        SigningAlgorithm.RS256.value,
    )

    assert "." in token


def test_build_pq_jwt_dilithium():

    builder = DeterministicJWTBuilder()

    token = builder._build_pq_jwt(
        {"sub": "user"},
        SigningAlgorithm.DILITHIUM_3.value,
    )

    assert "." in token