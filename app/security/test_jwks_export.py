from app.security.federation.keys import SigningKeyRegistry
from app.security.federation.jwks import export_jwks


def test_jwks_export_contains_public_key():

    registry = SigningKeyRegistry()
    key = registry.generate_and_register()

    jwks = export_jwks(registry)

    assert "keys" in jwks
    assert len(jwks["keys"]) == 1

    exported = jwks["keys"][0]

    assert exported["kid"] == key.kid
    assert exported["kty"] == "OKP"
    assert exported["crv"] == "Ed25519"
    assert exported["alg"] == "EdDSA"
    assert exported["use"] == "sig"
    assert "x" in exported
