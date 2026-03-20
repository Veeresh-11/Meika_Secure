# app/security/federation/discovery.py

class OIDCDiscoveryDocument:

    def __init__(self, issuer: str):
        self.issuer = issuer

    def build(self) -> dict:
        return {
            "issuer": self.issuer,
            "jwks_uri": f"{self.issuer}/jwks.json",
            "id_token_signing_alg_values_supported": ["EdDSA"],
            "response_types_supported": ["token"],
            "subject_types_supported": ["public"],
            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        }
