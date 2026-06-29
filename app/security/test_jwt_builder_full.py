# app/security/test_jwt_builder_full.py

from datetime import datetime

from app.security.federation.jwt_builder import (
    DeterministicJWTBuilder,
)


class FakePQSigner:
    algorithm = "ML-DSA"

    def sign(self, message, force_algorithm=None):
        return "pq_signature"


# --------------------------------------------------
# issued_at None branch
# --------------------------------------------------

def test_build_with_default_issued_at():

    builder = DeterministicJWTBuilder(
        pq_signer=FakePQSigner(),
    )

    class SigningKey:
        private_key = "secret"
        kid = "kid1"

    token = builder.build(
        signing_key=SigningKey(),
        principal_id="user1",
        audience="api",
        evidence_hash="ev1",
        device_state_hash="dev1",
        policy_version="v1",
    )

    assert isinstance(token, str)
    assert len(token) > 0


# --------------------------------------------------
# hasattr(private_key) branch
# --------------------------------------------------

def test_build_with_private_key_branch():

    builder = DeterministicJWTBuilder(
        pq_signer=FakePQSigner(),
    )

    class SigningKey:
        private_key = "secret"
        kid = "kid2"

    token = builder.build(
        signing_key=SigningKey(),
        principal_id="user2",
        audience="api",
        evidence_hash="ev2",
        device_state_hash="dev2",
        policy_version="v1",
        issued_at=datetime.utcnow(),
    )

    assert isinstance(token, str)


# --------------------------------------------------
# except Exception branch
# --------------------------------------------------

def test_build_fallback_to_pq_when_jwt_encode_fails(
    monkeypatch,
):

    builder = DeterministicJWTBuilder(
        pq_signer=FakePQSigner(),
    )

    class SigningKey:
        private_key = "secret"
        kid = "kid3"

    def explode(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "app.security.federation.jwt_builder.jwt.encode",
        explode,
    )

    token = builder.build(
        signing_key=SigningKey(),
        principal_id="user3",
        audience="api",
        evidence_hash="ev3",
        device_state_hash="dev3",
        policy_version="v1",
        issued_at=datetime.utcnow(),
    )

    assert token.count(".") == 2


# --------------------------------------------------
# no private_key branch
# --------------------------------------------------

def test_build_direct_pq_path():

    builder = DeterministicJWTBuilder(
        pq_signer=FakePQSigner(),
    )

    class SigningKey:
        pass

    token = builder.build(
        signing_key=SigningKey(),
        principal_id="user4",
        audience="api",
        evidence_hash="ev4",
        device_state_hash="dev4",
        policy_version="v1",
        issued_at=datetime.utcnow(),
    )

    assert token.count(".") == 2