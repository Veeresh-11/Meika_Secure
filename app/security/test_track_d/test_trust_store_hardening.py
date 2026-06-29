import pytest

from app.security.track_d.signing.trust_store import TrustStore


def _store():
    return TrustStore()


def _add(store, key_id="k1"):
    store.add_trusted_key(
        key_id=key_id,
        public_key_bytes=b"abc",
        created_at="2026-01-01T00:00:00Z",
    )
    
def test_invalid_timestamp_rejected():

    store = _store()

    with pytest.raises(ValueError):
        store.add_trusted_key(
            key_id="k1",
            public_key_bytes=b"abc",
            created_at="bad",
        )
        
def test_key_collision():

    store = _store()

    _add(store)

    with pytest.raises(ValueError):
        _add(store)

def test_public_key_must_be_bytes():

    store = _store()

    with pytest.raises(ValueError):
        store.add_trusted_key(
            key_id="k1",
            public_key_bytes="abc",
            created_at="2026-01-01T00:00:00Z",
        )
        
def test_invalid_weight():

    store = _store()

    with pytest.raises(ValueError):
        store.add_trusted_key(
            key_id="k1",
            public_key_bytes=b"abc",
            created_at="2026-01-01T00:00:00Z",
            weight=0,
        )

def test_hardware_root_requires_hsm():

    store = _store()

    with pytest.raises(ValueError):
        store.add_trusted_key(
            key_id="k1",
            public_key_bytes=b"abc",
            created_at="2026-01-01T00:00:00Z",
            hardware_root=True,
            provider="software",
        )
        
def test_expiry_before_creation():

    store = _store()

    with pytest.raises(ValueError):
        store.add_trusted_key(
            key_id="k1",
            public_key_bytes=b"abc",
            created_at="2026-01-02T00:00:00Z",
            expires_at="2026-01-01T00:00:00Z",
        )
        
def test_revoke_unknown_key():

    store = _store()

    with pytest.raises(ValueError):
        store.revoke(
            "missing",
            "2026-01-02T00:00:00Z",
        )
        
def test_revoke_before_creation():

    store = _store()

    _add(store)

    with pytest.raises(ValueError):
        store.revoke(
            "k1",
            "2025-01-01T00:00:00Z",
        )
        
@pytest.mark.parametrize(
    "func",
    [
        lambda s: s.validate_lifecycle(
            "missing",
            "2026-01-01T00:00:00Z",
        ),
        lambda s: s.get_public_key("missing"),
        lambda s: s.get_weight("missing"),
        lambda s: s.get_roles("missing"),
        lambda s: s.get_algorithm("missing"),
        lambda s: s.get_provider("missing"),
        lambda s: s.is_hardware_root("missing"),
        lambda s: s.get_metadata("missing"),
    ],
)
def test_unknown_key_branches(func):

    store = _store()

    with pytest.raises(ValueError):
        func(store)
        
def test_integrity_invalid_public_key():

    store = _store()

    _add(store)

    store._trusted["k1"]["public_key"] = "bad"

    assert store.validate_integrity() is False


def test_integrity_invalid_weight():

    store = _store()

    _add(store)

    store._trusted["k1"]["weight"] = 0

    assert store.validate_integrity() is False


def test_integrity_invalid_hardware_binding():

    store = _store()

    _add(store)

    store._trusted["k1"]["hardware_root"] = True
    store._trusted["k1"]["provider"] = "software"

    assert store.validate_integrity() is False
    
def test_register_key_wrapper():

    store = TrustStore()

    store.register_key(
        key_id="k1",
        public_key=b"abc",
        algorithm="Ed25519",
        weight=1,
        roles=["admin"],
        created_at="2026-01-01T00:00:00Z",
    )

    assert store.get_weight("k1") == 1
    
def test_revoke_success():

    store = TrustStore()

    store.add_trusted_key(
        key_id="k1",
        public_key_bytes=b"abc",
        created_at="2026-01-01T00:00:00Z",
    )

    store.revoke(
        "k1",
        "2026-01-02T00:00:00Z",
    )

    assert store._trusted["k1"]["revoked_at"] is not None
    
def test_validate_lifecycle_success():

    store = TrustStore()

    store.add_trusted_key(
        key_id="k1",
        public_key_bytes=b"abc",
        created_at="2026-01-01T00:00:00Z",
    )

    store.validate_lifecycle(
        "k1",
        "2026-01-02T00:00:00Z",
    )
    
def test_validate_lifecycle_revoked():

    store = TrustStore()

    store.add_trusted_key(
        key_id="k1",
        public_key_bytes=b"abc",
        created_at="2026-01-01T00:00:00Z",
    )

    store.revoke(
        "k1",
        "2026-01-02T00:00:00Z",
    )

    with pytest.raises(ValueError, match="Key revoked"):
        store.validate_lifecycle(
            "k1",
            "2026-01-03T00:00:00Z",
        )
        
def test_validate_lifecycle_expired():

    store = TrustStore()

    store.add_trusted_key(
        key_id="k1",
        public_key_bytes=b"abc",
        created_at="2026-01-01T00:00:00Z",
        expires_at="2026-01-02T00:00:00Z",
    )

    with pytest.raises(ValueError, match="Key expired"):
        store.validate_lifecycle(
            "k1",
            "2026-01-03T00:00:00Z",
        )
        
def test_accessors_success():

    store = TrustStore()

    store.add_trusted_key(
        key_id="k1",
        public_key_bytes=b"abc",
        created_at="2026-01-01T00:00:00Z",
        provider="hsm",
        hardware_root=True,
        weight=7,
        roles=["admin"],
    )

    assert store.get_public_key("k1") == b"abc"
    assert store.get_weight("k1") == 7
    assert store.get_roles("k1") == ["admin"]
    assert store.get_algorithm("k1") == "Ed25519"
    assert store.get_provider("k1") == "hsm"
    assert store.is_hardware_root("k1") is True

    metadata = store.get_metadata("k1")

    assert metadata["weight"] == 7
    
def test_validate_integrity_success():

    store = TrustStore()

    store.add_trusted_key(
        key_id="k1",
        public_key_bytes=b"abc",
        created_at="2026-01-01T00:00:00Z",
    )

    store.add_trusted_key(
        key_id="k2",
        public_key_bytes=b"def",
        created_at="2026-01-01T00:00:00Z",
    )

    assert store.validate_integrity() is True
    
def test_validate_lifecycle_before_activation():

    store = TrustStore()

    store.add_trusted_key(
        key_id="k1",
        public_key_bytes=b"abc",
        created_at="2026-01-02T00:00:00Z",
    )

    with pytest.raises(ValueError, match="before activation"):
        store.validate_lifecycle(
            "k1",
            "2026-01-01T00:00:00Z",
        )