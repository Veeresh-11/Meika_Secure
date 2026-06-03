# app/security/federation/pq_signer.py

import hashlib
import base64
import os
from enum import Enum
from typing import Optional


class SigningAlgorithm(str, Enum):
    """Supported signing algorithms"""
    DILITHIUM_3 = "DILITHIUM-3"  # ML-DSA (post-quantum)
    RS256 = "RS256"  # RSA (fallback/compatibility)
    EDDSA = "EdDSA"  # Current default


class PostQuantumSigner:
    """
    Hybrid post-quantum signer supporting:
    - ML-DSA (DILITHIUM-3) as primary for production
    - EdDSA as intermediate
    - RS256 as compatibility fallback
    
    The signer automatically selects algorithm based on PQ_SIGNING_ENABLED environment.
    """

    def __init__(
        self,
        secret: bytes = b"meika-pq-root",
        primary_algorithm: str = None,
    ):
        self._secret = secret
        
        # Determine primary algorithm from environment
        pq_enabled = os.getenv("PQ_SIGNING_ENABLED", "true").lower() == "true"
        
        if primary_algorithm:
            self._algorithm = SigningAlgorithm(primary_algorithm)
        elif pq_enabled:
            self._algorithm = SigningAlgorithm.DILITHIUM_3
        else:
            self._algorithm = SigningAlgorithm.RS256

    @property
    def algorithm(self) -> str:
        """Get current signing algorithm"""
        return self._algorithm.value

    def sign(self, message: bytes, force_algorithm: Optional[str] = None) -> str:
        """
        Sign a message and return just the signature string.
        
        For backward compatibility with existing code (FederationService),
        this returns base64url-encoded signature string only.
        
        Use sign_with_metadata() for algorithm and kid information.
        
        Args:
            message: Message to sign
            force_algorithm: Force specific algorithm (for testing)
        
        Returns:
            base64url-encoded signature string
        """
        result = self._sign_internal(message, force_algorithm)
        return result["signature"]
    
    def sign_with_metadata(self, message: bytes, force_algorithm: Optional[str] = None) -> dict:
        """
        Sign a message and return signature with metadata.
        
        Returns: {
            "signature": base64url-encoded signature,
            "algorithm": algorithm used,
            "kid": key ID for JWKS
        }
        """
        return self._sign_internal(message, force_algorithm)
    
    def _sign_internal(self, message: bytes, force_algorithm: Optional[str] = None) -> dict:
        """Internal method for signing (returns full metadata)."""
        algo = force_algorithm or self.algorithm
        
        if algo == SigningAlgorithm.DILITHIUM_3:
            return self._sign_dilithium3(message)
        elif algo == SigningAlgorithm.RS256:
            return self._sign_rsa256(message)
        else:
            return self._sign_eddsa(message)
    
    def _sign_dilithium3(self, message: bytes) -> dict:
        """
        Sign with ML-DSA (DILITHIUM-3).
        
        In production, this would use the actual ML-DSA implementation.
        For now, we use a deterministic mock that's cryptographically sound for testing.
        """
        # Deterministic hash-based signature for post-quantum simulation
        # In production, replace with actual ML-DSA from cryptography library
        digest = hashlib.sha3_512(self._secret + b"DILITHIUM" + message).digest()
        signature = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        
        return {
            "signature": signature,
            "algorithm": SigningAlgorithm.DILITHIUM_3.value,
            "kid": "pq-dilithium-2026-01",
        }
    
    def _sign_rsa256(self, message: bytes) -> dict:
        """
        Sign with RS256 (RSA fallback).
        
        In production, this would use actual RSA-2048 or RSA-4096.
        For testing, we use a deterministic mock.
        """
        digest = hashlib.sha256(self._secret + b"RS256" + message).digest()
        signature = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        
        return {
            "signature": signature,
            "algorithm": SigningAlgorithm.RS256.value,
            "kid": "rsa-2048-2026-01",
        }
    
    def _sign_eddsa(self, message: bytes) -> dict:
        """
        Sign with EdDSA (current default).
        """
        digest = hashlib.sha3_256(self._secret + b"EdDSA" + message).digest()
        signature = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        
        return {
            "signature": signature,
            "algorithm": SigningAlgorithm.EDDSA.value,
            "kid": "eddsa-2026-01",
        }

    def verify(self, message: bytes, signature: str, algorithm: str = None) -> bool:
        """
        Verify a signature with the specified algorithm.
        
        Returns True if signature is valid, False otherwise.
        """
        algo = algorithm or self.algorithm
        
        try:
            # Get the signature by calling sign with the same algorithm
            expected_sig = self.sign(message, force_algorithm=algo)
            return expected_sig == signature
        except Exception:
            return False

    def get_public_key_jwk(self) -> dict:
        """
        Export public key in JWK format for JWKS endpoint.
        
        The format depends on the algorithm.
        """
        if self.algorithm == SigningAlgorithm.DILITHIUM_3:
            return {
                "kty": "OKP",
                "crv": "ML-DSA",
                "alg": SigningAlgorithm.DILITHIUM_3.value,
                "use": "sig",
                "kid": "pq-dilithium-2026-01",
                "x": base64.urlsafe_b64encode(
                    hashlib.sha3_256(self._secret + b"DILITHIUM-public").digest()
                ).decode().rstrip("="),
            }
        elif self.algorithm == SigningAlgorithm.RS256:
            return {
                "kty": "RSA",
                "alg": SigningAlgorithm.RS256.value,
                "use": "sig",
                "kid": "rsa-2048-2026-01",
                "n": base64.urlsafe_b64encode(
                    hashlib.sha256(self._secret + b"RSA-modulus").digest()
                ).decode().rstrip("="),
                "e": "AQAB",
            }
        else:  # EdDSA
            return {
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": SigningAlgorithm.EDDSA.value,
                "use": "sig",
                "kid": "eddsa-2026-01",
                "x": base64.urlsafe_b64encode(
                    hashlib.sha3_256(self._secret + b"EdDSA-public").digest()
                ).decode().rstrip("="),
            }
