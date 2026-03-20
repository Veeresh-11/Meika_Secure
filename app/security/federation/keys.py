# app/security/federation/keys.py

import base64
import hashlib
from datetime import datetime
from typing import Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization

from .models import SigningKey


class SigningKeyRegistry:

    def __init__(self):
        self._keys: Dict[str, SigningKey] = {}
        self._active_kid: str | None = None

    def generate_and_register(self) -> SigningKey:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        raw_pub = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        kid = hashlib.sha3_256(raw_pub).hexdigest()[:16]

        key = SigningKey(
            kid=kid,
            algorithm="EdDSA",
            private_key=private_key,
            public_key=public_key,
            created_at=datetime.utcnow(),
        )

        self._keys[kid] = key
        self._active_kid = kid
        return key

    def get_active(self) -> SigningKey:
        if not self._active_kid:
            raise RuntimeError("No active signing key")
        return self._keys[self._active_kid]

    def get(self, kid: str) -> SigningKey:
        return self._keys[kid]

    def export_jwks(self) -> dict:
        keys = []

        for key in self._keys.values():
            raw_pub = key.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

            keys.append({
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": key.kid,
                "alg": "EdDSA",
                "use": "sig",
                "x": base64.urlsafe_b64encode(raw_pub).decode().rstrip("="),
            })

        return {"keys": keys}
