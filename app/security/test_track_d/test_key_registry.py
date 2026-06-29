from datetime import datetime
import pytest

from app.security.track_d.signing.key_registry import KeyRegistry
from app.security.track_d.signing.ed25519_provider import Ed25519Signer
from app.security.track_d.signing.ed25519_local import Ed25519LocalSigner
from app.security.track_d.signing.key_registry import (SigningKeyStatus,SigningKeyMetadata)

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

def test_invalid_created_at_timestamp():

    registry = KeyRegistry()
    signer = Ed25519LocalSigner()

    with pytest.raises(ValueError):
        registry.register_key(
            key_id="k1",
            algorithm="Ed25519",
            created_at="bad",
            signer=signer,
        )
        
def test_duplicate_key():

    registry = KeyRegistry()
    signer = Ed25519LocalSigner()

    registry.register_key(
        key_id="k1",
        algorithm="Ed25519",
        created_at="2025-01-01T00:00:00Z",
        signer=signer,
    )

    with pytest.raises(ValueError):
        registry.register_key(
            key_id="k1",
            algorithm="Ed25519",
            created_at="2025-01-02T00:00:00Z",
            signer=signer,
        )
        
def test_algorithm_mismatch():

    registry = KeyRegistry()
    signer = Ed25519LocalSigner()

    with pytest.raises(ValueError):
        registry.register_key(
            key_id="k1",
            algorithm="RSA",
            created_at="2025-01-01T00:00:00Z",
            signer=signer,
        )
        
def test_expiry_before_creation():

    registry = KeyRegistry()
    signer = Ed25519LocalSigner()

    with pytest.raises(ValueError):
        registry.register_key(
            key_id="k1",
            algorithm="Ed25519",
            created_at="2025-01-02T00:00:00Z",
            expires_at="2025-01-01T00:00:00Z",
            signer=signer,
        )
        
def test_second_active_deactivates_first():

    registry = KeyRegistry()

    s1 = Ed25519LocalSigner()
    s2 = Ed25519LocalSigner()

    registry.register_key(
        key_id="a",
        algorithm="Ed25519",
        created_at="2025-01-01T00:00:00Z",
        signer=s1,
        make_active=True,
    )

    registry.register_key(
        key_id="b",
        algorithm="Ed25519",
        created_at="2025-01-02T00:00:00Z",
        signer=s2,
        make_active=True,
    )

    assert registry.get("a").status == SigningKeyStatus.DEPRECATED
    assert registry.get("b").status == SigningKeyStatus.ACTIVE
    
def test_unknown_revoke():

    registry = KeyRegistry()

    with pytest.raises(ValueError):
        registry.revoke("missing")
        
def test_revoke_twice():

    registry = KeyRegistry()
    signer = Ed25519LocalSigner()

    registry.register_key(
        key_id="k1",
        algorithm="Ed25519",
        created_at="2025-01-01T00:00:00Z",
        signer=signer,
    )

    registry.revoke("k1")

    with pytest.raises(ValueError):
        registry.revoke("k1")
        
def test_revoke_before_creation():

    registry = KeyRegistry()
    signer = Ed25519LocalSigner()

    registry.register_key(
        key_id="k1",
        algorithm="Ed25519",
        created_at="2025-02-01T00:00:00Z",
        signer=signer,
    )

    with pytest.raises(ValueError):
        registry.revoke(
            "k1",
            revoked_at="2025-01-01T00:00:00Z",
        )
        
from datetime import datetime, timezone
from unittest.mock import patch

def test_active_key_expired():

    registry = KeyRegistry()
    signer = Ed25519LocalSigner()

    registry.register_key(
        key_id="k1",
        algorithm="Ed25519",
        signer=signer,
        make_active=True,
        created_at="2025-01-01T00:00:00Z",
        expires_at="2025-01-02T00:00:00Z",
    )

    with patch(
        "app.security.track_d.signing.key_registry._utc_now",
        return_value=datetime(
            2025, 1, 3, tzinfo=timezone.utc
        ),
    ):
        with pytest.raises(ValueError, match="Active key expired"):
            registry.get_active()
            
def test_unknown_get():

    registry = KeyRegistry()

    with pytest.raises(ValueError):
        registry.get("missing")
        
def test_validate_integrity_detects_two_active():

    registry = KeyRegistry()

    s1 = Ed25519LocalSigner()
    s2 = Ed25519LocalSigner()

    registry.register_key(
        key_id="k1",
        algorithm="Ed25519",
        created_at="2025-01-01T00:00:00Z",
        signer=s1,
        make_active=True,
    )

    registry._keys["k2"] = SigningKeyMetadata(
        key_id="k2",
        algorithm="Ed25519",
        created_at=registry.get("k1").created_at,
        expires_at=None,
        revoked_at=None,
        status=SigningKeyStatus.ACTIVE,
        signer=s2,
    )

    assert registry.validate_integrity() is False
    
