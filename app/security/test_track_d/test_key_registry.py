from datetime import datetime
import pytest

from app.security.track_d.signing.key_registry import KeyRegistry
from app.security.track_d.signing.ed25519_provider import Ed25519Signer


def test_single_active_key():
    registry = KeyRegistry()

    signer = Ed25519Signer.generate()

    registry.register_key(
        key_id="key-1",
        algorithm="Ed25519",
        created_at="2026-01-01T00:00:00Z",
        signer=signer,
        make_active=True,
    )

    active = registry.get_active_signer()
    assert active.key_id == "key-1"


def test_rotation():
    registry = KeyRegistry()

    signer1 = Ed25519Signer.generate()
    signer2 = Ed25519Signer.generate()

    registry.register_key(
        key_id="key-1",
        algorithm="Ed25519",
        created_at="2026-01-01T00:00:00Z",
        signer=signer1,
        make_active=True,
    )

    registry.rotate(
        key_id="key-2",
        algorithm="Ed25519",
        created_at="2026-02-01T00:00:00Z",
        signer=signer2,
    )

    active = registry.get_active_signer()
    assert active.key_id == "key-2"


def test_revoked_key_not_active():
    registry = KeyRegistry()
    signer = Ed25519Signer.generate()

    registry.register_key(
        key_id="key-1",
        algorithm="Ed25519",
        created_at="2026-01-01T00:00:00Z",
        signer=signer,
        make_active=True,
    )

    registry.revoke("key-1")

    with pytest.raises(ValueError):
        registry.get_active_signer()
