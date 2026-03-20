from app.security.federation.discovery import OIDCDiscoveryDocument


def test_discovery_document_structure():

    doc = OIDCDiscoveryDocument("https://meika.local").build()

    assert doc["issuer"] == "https://meika.local"
    assert "jwks_uri" in doc
