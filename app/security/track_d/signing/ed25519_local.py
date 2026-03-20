"""
TRACK D — Local Ed25519 Signer (Constitutional Hardened)
"""

from __future__ import annotations

import hashlib
import json  # required for some test imports

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from .signer_interface import ISigner


class Ed25519LocalSigner(ISigner):

    def __init__(self, private_key: Ed25519PrivateKey | None = None):

        if private_key:
            self._private_key = private_key
        else:
            seed = hashlib.sha256(
                b"meika-deterministic-dev-key"
            ).digest()

            self._private_key = Ed25519PrivateKey.from_private_bytes(
                seed[:32]
            )

        self._public_key = self._private_key.public_key()
        self._key_id = self._derive_key_id()

    # ---------------------------------------------------------
    # Signing
    # ---------------------------------------------------------

    def sign(self, message: bytes):
        """
        Returns (signature_hex, key_id)
        This matches legacy Track D test contract.
        """
        signature = self._private_key.sign(message)
        return signature.hex(), self._key_id

    # ---------------------------------------------------------
    # Verification (needed by SOC2 tests)
    # ---------------------------------------------------------

    def verify(self, message: bytes, signature_hex: str) -> bool:
        try:
            self._public_key.verify(
                bytes.fromhex(signature_hex),
                message,
            )
            return True
        except InvalidSignature:
            return False

    # ---------------------------------------------------------
    # Metadata
    # ---------------------------------------------------------

    def algorithm(self) -> str:
        return "Ed25519"

    def key_id(self) -> str:
        return self._key_id

    def public_key_hex(self) -> str:
        return self.public_key_bytes().hex()

    def is_hardware(self) -> bool:
        return False

    def public_key_bytes(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    # ---------------------------------------------------------
    # Internal
    # ---------------------------------------------------------

    def _derive_key_id(self) -> str:
        pub = self.public_key_bytes()
        return hashlib.sha256(pub).hexdigest()

