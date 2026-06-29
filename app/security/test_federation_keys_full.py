# app/security/test_federation_keys_full.py

import pytest

from app.security.federation.keys import SigningKeyRegistry


def test_get_active_without_key_raises():

    registry = SigningKeyRegistry()

    with pytest.raises(RuntimeError):
        registry.get_active()


def test_export_jwks():

    registry = SigningKeyRegistry()

    key = registry.generate_and_register()

    jwks = registry.export_jwks()

    assert "keys" in jwks
    assert len(jwks["keys"]) == 1

    entry = jwks["keys"][0]

    assert entry["kty"] == "OKP"
    assert entry["crv"] == "Ed25519"
    assert entry["alg"] == "EdDSA"
    assert entry["use"] == "sig"
    assert entry["kid"] == key.kid
    assert isinstance(entry["x"], str)
    assert len(entry["x"]) > 0
    
def test_get_active_returns_key():

    registry = SigningKeyRegistry()

    key = registry.generate_and_register()

    active = registry.get_active()

    assert active == key
    assert active.kid == key.kid


def test_get_by_kid():

    registry = SigningKeyRegistry()

    key = registry.generate_and_register()

    result = registry.get(key.kid)

    assert result == key
    assert result.kid == key.kid