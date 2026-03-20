# app/security/federation/jwt_builder.py

import hashlib
from datetime import datetime, timedelta
from typing import Dict

import jwt

from app.security.version import KERNEL_VERSION, KERNEL_BUILD_HASH


class DeterministicJWTBuilder:

    def __init__(self, issuer: str = "meika-authority"):
        self.issuer = issuer

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
    ) -> str:

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
        }

        token = jwt.encode(
            claims,
            signing_key.private_key,
            algorithm="EdDSA",
            headers={"kid": signing_key.kid},
        )

        return token
