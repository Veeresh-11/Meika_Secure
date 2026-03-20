"""
TRACK D — Software Provider (Deterministic Ed25519)

Implements BaseProvider interface.

Security Properties:
- Deterministic Ed25519 signing
- No external I/O
- Fail-closed key access
- Explicit hardware=false signaling
"""

from __future__ import annotations

from typing import Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization

from .base_provider import HSMProvider


class SoftwareProvider(HSMProvider):
    """
    Pure software-based signing provider.
    Intended for development / non-hardware environments.
    """

    def __init__(self):
        self._keys: Dict[str, Ed25519PrivateKey] = {}

    # ---------------------------------------------------------
    # Key Management
    # ---------------------------------------------------------

    def generate_key(self, key_id: str) -> None:
        if key_id in self._keys:
            raise ValueError("Key already exists in software provider")

        private = Ed25519PrivateKey.generate()
        self._keys[key_id] = private

    def import_key(self, key_id: str, private_key: Ed25519PrivateKey) -> None:
        if key_id in self._keys:
            raise ValueError("Key already exists")

        self._keys[key_id] = private_key

    # ---------------------------------------------------------
    # Signing
    # ---------------------------------------------------------

    def sign(self, key_id: str, message: bytes) -> bytes:
        if key_id not in self._keys:
            raise ValueError("Key not found in software provider")

        private = self._keys[key_id]
        return private.sign(message)  # Ed25519 is deterministic

    # ---------------------------------------------------------
    # Public Key Access
    # ---------------------------------------------------------

    def get_public_key(self, key_id: str) -> bytes:
        if key_id not in self._keys:
            raise ValueError("Key not found in software provider")

        return self._keys[key_id].public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    # ---------------------------------------------------------
    # Provider Metadata
    # ---------------------------------------------------------

    def is_hardware(self) -> bool:
        return False
