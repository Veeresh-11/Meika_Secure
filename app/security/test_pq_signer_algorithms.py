"""
Tests for Post-Quantum Signer Implementation (P0.1)

Tests for the hybrid post-quantum signer supporting ML-DSA (DILITHIUM-3),
RS256, and EdDSA algorithms with automatic selection and backward compatibility.
"""

import pytest
import os
import base64
from app.security.federation.pq_signer import PostQuantumSigner, SigningAlgorithm


@pytest.fixture
def test_message():
    """Standard test message for signing operations."""
    return b"test-message-to-sign"


@pytest.fixture(autouse=True)
def reset_pq_env():
    """Reset PQ_SIGNING_ENABLED to its original state after each test."""
    original_state = os.environ.get("PQ_SIGNING_ENABLED")
    yield
    if original_state is None:
        os.environ.pop("PQ_SIGNING_ENABLED", None)
    else:
        os.environ["PQ_SIGNING_ENABLED"] = original_state


class TestPostQuantumSignerAlgorithms:
    """Test algorithm-specific signing implementations."""
    
    def test_dilithium3_signing(self, test_message):
        """Test: ML-DSA (DILITHIUM-3) algorithm signing."""
        signer = PostQuantumSigner(primary_algorithm=SigningAlgorithm.DILITHIUM_3)
        
        # Sign the message
        signature = signer.sign(test_message)
        
        # Verify we get a base64url encoded string
        assert isinstance(signature, str)
        assert len(signature) > 0
    
    def test_rs256_signing(self, test_message):
        """Test: RS256 (RSA) algorithm signing."""
        signer = PostQuantumSigner(primary_algorithm=SigningAlgorithm.RS256)
        
        signature = signer.sign(test_message)
        
        assert isinstance(signature, str)
        assert len(signature) > 0
    
    def test_eddsa_signing(self, test_message):
        """Test: EdDSA algorithm signing."""
        signer = PostQuantumSigner(primary_algorithm=SigningAlgorithm.EDDSA)
        
        signature = signer.sign(test_message)
        
        assert isinstance(signature, str)
        assert len(signature) > 0


class TestBackwardCompatibility:
    """Test backward compatibility of the sign() method."""
    
    def test_sign_returns_string_not_dict(self, test_message):
        """Test: sign() method returns string for backward compatibility."""
        signer = PostQuantumSigner()
        
        result = signer.sign(test_message)
        
        # CRITICAL: sign() must return a string for backward compatibility
        # with existing code like FederationService.issue_token()
        assert isinstance(result, str), "sign() must return str, not dict"
        assert not isinstance(result, dict), "sign() must not return dict"
    
    def test_federation_service_compatibility(self, test_message):
        """Test: Verify backward compatibility with FederationService usage pattern."""
        signer = PostQuantumSigner()
        
        # This is how FederationService.issue_token() calls the signer
        binding_hash = test_message
        signature = signer.sign(binding_hash)
        
        # Should be a plain base64url string
        assert isinstance(signature, str)
        # Should be valid base64 (plus potential no-padding)
        # Try to decode it
        padded = signature + "=" * (4 - len(signature) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        assert isinstance(decoded, bytes)
        assert len(decoded) > 0


class TestNewSignWithMetadata:
    """Test new sign_with_metadata() method for new use cases."""
    
    def test_sign_with_metadata_returns_dict(self, test_message):
        """Test: sign_with_metadata() returns dict with full metadata."""
        signer = PostQuantumSigner()
        
        result = signer.sign_with_metadata(test_message)
        
        # Must be a dict
        assert isinstance(result, dict)
        # Must have required keys
        assert "signature" in result
        assert "algorithm" in result
        assert "kid" in result
        
        # signature should be a string
        assert isinstance(result["signature"], str)
        # algorithm should match our algorithm
        assert result["algorithm"] in [
            SigningAlgorithm.DILITHIUM_3,
            SigningAlgorithm.RS256,
            SigningAlgorithm.EDDSA
        ]
    
    def test_sign_with_metadata_includes_algorithm(self):
        """Test: sign_with_metadata includes correct algorithm in result."""
        message = b"test-message"
        
        # Test DILITHIUM-3
        signer = PostQuantumSigner(primary_algorithm=SigningAlgorithm.DILITHIUM_3)
        result = signer.sign_with_metadata(message)
        assert result["algorithm"] == SigningAlgorithm.DILITHIUM_3.value
        
        # Test RS256
        signer = PostQuantumSigner(primary_algorithm=SigningAlgorithm.RS256)
        result = signer.sign_with_metadata(message)
        assert result["algorithm"] == SigningAlgorithm.RS256.value
        
        # Test EdDSA
        signer = PostQuantumSigner(primary_algorithm=SigningAlgorithm.EDDSA)
        result = signer.sign_with_metadata(message)
        assert result["algorithm"] == SigningAlgorithm.EDDSA.value


class TestForceAlgorithm:
    """Test force_algorithm parameter overrides default."""
    
    def test_force_algorithm_override(self, test_message):
        """Test: force_algorithm overrides default algorithm."""
        # Create signer with DILITHIUM-3 default
        signer = PostQuantumSigner(primary_algorithm=SigningAlgorithm.DILITHIUM_3)
        
        # Force it to use RS256
        result = signer.sign_with_metadata(
            test_message,
            force_algorithm=SigningAlgorithm.RS256
        )
        
        # Should use RS256 despite default being DILITHIUM-3
        assert result["algorithm"] == SigningAlgorithm.RS256.value
    
    def test_sign_respects_force_algorithm(self, test_message):
        """Test: sign() method respects force_algorithm parameter."""
        signer = PostQuantumSigner(primary_algorithm=SigningAlgorithm.DILITHIUM_3)
        
        # Signature 1 with forced EdDSA
        sig1 = signer.sign(test_message, force_algorithm=SigningAlgorithm.EDDSA)
        
        # Signature 2 with forced RS256
        sig2 = signer.sign(test_message, force_algorithm=SigningAlgorithm.RS256)
        
        # With deterministic implementations, signatures might differ
        # (This is testing that the force parameter is accepted and works)
        assert isinstance(sig1, str)
        assert isinstance(sig2, str)


class TestEnvironmentBasedSelection:
    """Test PQ_SIGNING_ENABLED environment variable controls default selection."""
    
    def test_pq_enabled_defaults_to_dilithium3(self, test_message):
        """Test: PQ_SIGNING_ENABLED=true makes DILITHIUM-3 default."""
        os.environ["PQ_SIGNING_ENABLED"] = "true"
        
        signer = PostQuantumSigner()
        
        result = signer.sign_with_metadata(test_message)
        assert result["algorithm"] == SigningAlgorithm.DILITHIUM_3.value
    
    def test_pq_disabled_defaults_to_rs256(self, test_message):
        """Test: PQ_SIGNING_ENABLED=false makes RS256 default."""
        os.environ["PQ_SIGNING_ENABLED"] = "false"
        
        signer = PostQuantumSigner()
        
        result = signer.sign_with_metadata(test_message)
        assert result["algorithm"] == SigningAlgorithm.RS256.value
    
    def test_pq_not_set_defaults_to_dilithium3(self, test_message):
        """Test: Without PQ_SIGNING_ENABLED env var, defaults to DILITHIUM-3."""
        os.environ.pop("PQ_SIGNING_ENABLED", None)
        
        signer = PostQuantumSigner()
        
        result = signer.sign_with_metadata(test_message)
        # Default is DILITHIUM-3 when not specified
        assert result["algorithm"] == SigningAlgorithm.DILITHIUM_3.value


class TestJWKPublicKeyExport:
    """Test JWK format public key export for federation."""
    
    def test_get_public_key_jwk_returns_dict(self):
        """Test: get_public_key_jwk() returns JWK format dict."""
        signer = PostQuantumSigner()
        
        jwk = signer.get_public_key_jwk()
        
        assert isinstance(jwk, dict)
        assert "kty" in jwk  # Key type
        assert "kid" in jwk  # Key ID
    
    def test_jwk_includes_key_id_for_algorithm(self):
        """Test: JWK includes consistent key ID that varies by algorithm."""
        # Test DILITHIUM-3
        signer_dilithium = PostQuantumSigner(primary_algorithm=SigningAlgorithm.DILITHIUM_3)
        jwk_dilithium = signer_dilithium.get_public_key_jwk()
        assert jwk_dilithium["kid"] == "pq-dilithium-2026-01"
        
        # Test RS256
        signer_rsa = PostQuantumSigner(primary_algorithm=SigningAlgorithm.RS256)
        jwk_rsa = signer_rsa.get_public_key_jwk()
        assert jwk_rsa["kid"] == "rsa-2048-2026-01"
        
        # Test EdDSA
        signer_eddsa = PostQuantumSigner(primary_algorithm=SigningAlgorithm.EDDSA)
        jwk_eddsa = signer_eddsa.get_public_key_jwk()
        assert jwk_eddsa["kid"] == "eddsa-2026-01"


class TestDeterministicSigning:
    """Test deterministic signing for test reproducibility."""
    
    def test_deterministic_signature_same_message(self):
        """Test: Same message produces consistent signature."""
        message = b"consistent-message"
        signer = PostQuantumSigner()
        
        sig1 = signer.sign(message)
        sig2 = signer.sign(message)
        
        # With deterministic implementations, same message should produce same signature
        assert sig1 == sig2


class TestEmptyAndLargeMessages:
    """Test signer handles edge cases."""
    
    def test_sign_empty_message(self):
        """Test: Can sign empty message."""
        signer = PostQuantumSigner()
        
        signature = signer.sign(b"")
        
        assert isinstance(signature, str)
        assert len(signature) > 0
    
    def test_sign_large_message(self):
        """Test: Can sign large message (1 MB)."""
        signer = PostQuantumSigner()
        
        large_message = b"x" * (1024 * 1024)  # 1 MB
        
        signature = signer.sign(large_message)
        
        assert isinstance(signature, str)
        assert len(signature) > 0
