import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from app.security.track_d.signing.ed25519_local import (
    Ed25519LocalSigner,
)


def test_injected_private_key():
    key = Ed25519PrivateKey.generate()

    signer = Ed25519LocalSigner(key)

    assert signer.algorithm() == "Ed25519"


def test_env_private_key(monkeypatch):
    key = Ed25519PrivateKey.generate()

    raw = key.private_bytes_raw()

    monkeypatch.setenv(
        "SIGNING_PRIVATE_KEY",
        raw.hex(),
    )

    signer = Ed25519LocalSigner()

    assert signer.algorithm() == "Ed25519"


def test_invalid_env_key(monkeypatch):
    monkeypatch.setenv(
        "SIGNING_PRIVATE_KEY",
        "abcd",
    )

    with pytest.raises(
        RuntimeError,
        match="Invalid SIGNING_PRIVATE_KEY format",
    ):
        Ed25519LocalSigner()


def test_random_generation(monkeypatch):
    monkeypatch.delenv(
        "SIGNING_PRIVATE_KEY",
        raising=False,
    )

    signer = Ed25519LocalSigner()

    assert signer.algorithm() == "Ed25519"


def test_sign_verify():
    signer = Ed25519LocalSigner()

    sig, kid = signer.sign(b"hello")

    assert signer.verify(b"hello", sig)
    assert kid == signer.key_id()


def test_verify_failure():
    signer = Ed25519LocalSigner()

    sig, _ = signer.sign(b"hello")

    assert signer.verify(b"world", sig) is False


def test_public_key_hex():
    signer = Ed25519LocalSigner()

    assert len(signer.public_key_hex()) == 64


def test_public_key_bytes():
    signer = Ed25519LocalSigner()

    assert len(signer.public_key_bytes()) == 32


def test_key_id():
    signer = Ed25519LocalSigner()

    assert len(signer.key_id()) == 64


def test_is_hardware():
    signer = Ed25519LocalSigner()

    assert signer.is_hardware() is False