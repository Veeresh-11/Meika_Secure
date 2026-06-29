import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from app.security.track_d.signing.ed25519_provider import (
    Ed25519Signer,
)


def test_generate():
    signer = Ed25519Signer.generate()

    assert isinstance(signer, Ed25519Signer)


def test_sign_and_verify():
    signer = Ed25519Signer.generate()

    sig, key_id = signer.sign(b"hello")

    assert signer.verify(b"hello", sig)
    assert key_id == signer.key_id()


def test_verify_wrong_message():
    signer = Ed25519Signer.generate()

    sig, _ = signer.sign(b"hello")

    assert signer.verify(b"world", sig) is False


def test_verify_invalid_hex():
    signer = Ed25519Signer.generate()

    assert signer.verify(b"hello", "not-a-hex-string") is False


def test_algorithm():
    signer = Ed25519Signer.generate()

    assert signer.algorithm() == "Ed25519"


def test_public_key_bytes():
    signer = Ed25519Signer.generate()

    pk = signer.public_key_bytes()

    assert isinstance(pk, bytes)
    assert len(pk) == 32


def test_key_id():
    signer = Ed25519Signer.generate()

    assert len(signer.key_id()) == 64


def test_constructor():
    private = Ed25519PrivateKey.generate()

    signer = Ed25519Signer(private)

    assert signer.algorithm() == "Ed25519"