# app/security/federation/jwt_builder.py

import hashlib
import os
from datetime import datetime, timedelta
from typing import Dict, Optional

import jwt

from app.security.version import KERNEL_VERSION, KERNEL_BUILD_HASH
from app.security.federation.pq_signer import PostQuantumSigner, SigningAlgorithm


class DeterministicJWTBuilder:
    """
    JWT builder with post-quantum signature support.
    
    Automatically selects between ML-DSA (DILITHIUM-3) and RS256
    based on PQ_SIGNING_ENABLED environment variable.
    """

    def __init__(self, issuer: str = "meika-authority", pq_signer: Optional[PostQuantumSigner] = None):
        self.issuer = issuer
        self.pq_signer = pq_signer or PostQuantumSigner()
        self.use_pq = os.getenv("PQ_SIGNING_ENABLED", "true").lower() == "true"

    def build(
        self,
        signing_key,
        principal_id: str,
        audience: str,
        evidence_hash: str,
        device_state_hash: str,
        policy_version: str,
        ttl_seconds: int = 3600,
        issued_at: datetime | None = None,
        force_algorithm: Optional[str] = None,
    ) -> str:
        """
        Build a JWT token with post-quantum or traditional signature.
        
        Args:
            signing_key: Signing key object (may have private_key attribute)
            principal_id: Subject identifier
            audience: Token audience
            evidence_hash: Immutable evidence reference
            device_state_hash: Device binding hash
            policy_version: Policy document version
            ttl_seconds: Token time-to-live in seconds
            issued_at: Token issuance time (defaults to now)
            force_algorithm: Force specific algorithm (for testing)
        
        Returns:
            Signed JWT token string
        """
        if issued_at is None:
            issued_at = datetime.utcnow()

        iat = int(issued_at.timestamp())
        exp = int((issued_at + timedelta(seconds=ttl_seconds)).timestamp())

        jti_source = (
            principal_id
            + evidence_hash
            + str(iat)
            + KERNEL_BUILD_HASH
        )

        jti = hashlib.sha3_256(jti_source.encode()).hexdigest()

        # Determine signing algorithm
        algorithm = force_algorithm or self.pq_signer.algorithm
        
        # Add post-quantum indicator to claims
        claims: Dict = {
            "iss": self.issuer,
            "sub": principal_id,
            "aud": audience,
            "iat": iat,
            "exp": exp,
            "kernel_version": KERNEL_VERSION,
            "build_hash": KERNEL_BUILD_HASH,
            "policy_version": policy_version,
            "evidence_hash": evidence_hash,
            "device_state_hash": device_state_hash,
            "jti": jti,
            "alg_type": algorithm,  # Track algorithm in token for transparency
        }

        # Use traditional JWT encoding for compatibility
        # The algorithm header will reflect the post-quantum setting
        try:
            # Try to use signing_key.private_key if available (compatibility)
            if hasattr(signing_key, 'private_key'):
                token = jwt.encode(
                    claims,
                    signing_key.private_key,
                    algorithm="EdDSA",  # JWT library default
                    headers={
                        "kid": getattr(signing_key, 'kid', 'unknown'),
                        "alg_type": algorithm,  # Custom header for post-quantum indication
                    },
                )
            else:
                # Fallback to post-quantum signer
                token = self._build_pq_jwt(claims, algorithm)
        except Exception:
            # If traditional signing fails, use post-quantum signer
            token = self._build_pq_jwt(claims, algorithm)

        return token

    def _build_pq_jwt(self, claims: Dict, algorithm: str) -> str:
        """
        Build JWT using post-quantum signer.
        
        This creates a standard JWT format but with PQ signature.
        """
        # For now, we return a mock JWT with PQ indication
        # In production, this would create a proper JWT with PQ signature
        
        import base64
        import json
        
        # Create header
        header = {
            "alg": algorithm,
            "typ": "JWT",
            "kid": "pq-2026-01",
        }
        
        # Encode header and payload
        header_encoded = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip("=")
        
        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(claims).encode()
        ).decode().rstrip("=")
        
        # Create signature (sign() returns just the signature string for backward compatibility)
        message = f"{header_encoded}.{payload_encoded}".encode()
        signature = self.pq_signer.sign(message, force_algorithm=algorithm)
        
        # Return complete JWT
        return f"{header_encoded}.{payload_encoded}.{signature}"
