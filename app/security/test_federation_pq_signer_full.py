# app/security/test_federation_pq_signer_full.py

from unittest.mock import patch

from app.security.federation.pq_signer import (
    PostQuantumSigner,
    SigningAlgorithm,
)


def test_constructor_primary_algorithm():
    signer = PostQuantumSigner(
        primary_algorithm=SigningAlgorithm.EDDSA.value
    )

    assert signer.algorithm == SigningAlgorithm.EDDSA.value


def test_constructor_pq_disabled():
    with patch.dict(
        "os.environ",
        {"PQ_SIGNING_ENABLED": "false"},
        clear=False,
    ):
        signer = PostQuantumSigner()

    assert signer.algorithm == SigningAlgorithm.RS256.value


def test_sign_rs256():
    signer = PostQuantumSigner()

    result = signer.sign_with_metadata(
        b"hello",
        force_algorithm=SigningAlgorithm.RS256,
    )

    assert result["algorithm"] == SigningAlgorithm.RS256.value
    assert result["kid"] == "rsa-2048-2026-01"


def test_sign_eddsa():
    signer = PostQuantumSigner()

    result = signer.sign_with_metadata(
        b"hello",
        force_algorithm=SigningAlgorithm.EDDSA,
    )

    assert result["algorithm"] == SigningAlgorithm.EDDSA.value
    assert result["kid"] == "eddsa-2026-01"


def test_verify_exception_returns_false():
    signer = PostQuantumSigner()

    with patch.object(
        signer,
        "sign",
        side_effect=RuntimeError("boom"),
    ):
        assert signer.verify(
            b"msg",
            "sig",
        ) is False


def test_jwk_dilithium():
    signer = PostQuantumSigner(
        primary_algorithm=SigningAlgorithm.DILITHIUM_3.value
    )

    jwk = signer.get_public_key_jwk()

    assert jwk["alg"] == SigningAlgorithm.DILITHIUM_3.value
    assert jwk["kid"] == "pq-dilithium-2026-01"
    assert jwk["crv"] == "ML-DSA"


def test_jwk_rs256():
    signer = PostQuantumSigner(
        primary_algorithm=SigningAlgorithm.RS256.value
    )

    jwk = signer.get_public_key_jwk()

    assert jwk["alg"] == SigningAlgorithm.RS256.value
    assert jwk["kid"] == "rsa-2048-2026-01"
    assert jwk["e"] == "AQAB"


def test_jwk_eddsa():
    signer = PostQuantumSigner(
        primary_algorithm=SigningAlgorithm.EDDSA.value
    )

    jwk = signer.get_public_key_jwk()

    assert jwk["alg"] == SigningAlgorithm.EDDSA.value
    assert jwk["kid"] == "eddsa-2026-01"
    assert jwk["crv"] == "Ed25519"