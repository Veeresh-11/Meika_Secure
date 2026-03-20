# app/security/federation/jwks.py

from .keys import SigningKeyRegistry


def export_jwks(registry: SigningKeyRegistry) -> dict:
    """
    Public JWKS export surface.
    Delegates to SigningKeyRegistry.
    """
    return registry.export_jwks()
