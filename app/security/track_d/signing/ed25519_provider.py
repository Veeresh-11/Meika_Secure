"""
TRACK D — Ed25519 Signing Provider

Enterprise-ready signing provider.

Supports:
- Key generation
- Signing
- Verification
- Key identification
- Future HSM replacement
"""

from __future__ import annotations

import os
import hashlib
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


class Ed25519Signer:
    """
    Software-based Ed25519 signing provider.

    Designed to be replaceable with HSM-backed implementation.
    """

    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._key_id = self._derive_key_id()

    # -------------------------------------------------
    # Key Generation
    # -------------------------------------------------

    @classmethod
    def generate(cls) -> "Ed25519Signer":
        """
        Generate new Ed25519 keypair.
        """
        private_key = Ed25519PrivateKey.generate()
        return cls(private_key)

    # -------------------------------------------------
    # Signing
    # -------------------------------------------------

    def sign(self, data: bytes) -> Tuple[str, str]:
        signature = self._private_key.sign(data)
        return signature.hex(), self._key_id

    def verify(self, data: bytes, signature_hex: str) -> bool:
        try:
            signature = bytes.fromhex(signature_hex)
            self._public_key.verify(signature, data)
            return True
        except Exception:
            return False

    # -------------------------------------------------
    # Metadata
    # -------------------------------------------------

    def algorithm(self) -> str:
        return "Ed25519"

    def key_id(self) -> str:
        return self._key_id

    def public_key_bytes(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    # -------------------------------------------------
    # Internal
    # -------------------------------------------------

    def _derive_key_id(self) -> str:
        """
        Deterministic key identifier derived from public key.
        """
        pub = self.public_key_bytes()
        return hashlib.sha256(pub).hexdigest()
