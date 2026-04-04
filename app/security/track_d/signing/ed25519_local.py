"""
TRACK D — Local Ed25519 Signer (Constitutional Hardened)
"""

from __future__ import annotations

import os
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
        """
        Secure initialization:

        Priority:
        1. Injected key (tests / DI)
        2. Environment variable (production)
        3. Random key (safe dev fallback)
        """

        # -----------------------------------------
        # 1️⃣ Injected key (tests)
        # -----------------------------------------
        if private_key:
            self._private_key = private_key

        else:
            # -----------------------------------------
            # 2️⃣ Load from ENV (PRODUCTION)
            # -----------------------------------------
            key_hex = os.getenv("SIGNING_PRIVATE_KEY")

            if key_hex:
                try:
                    key_bytes = bytes.fromhex(key_hex)

                    if len(key_bytes) != 32:
                        raise ValueError("Invalid key length")

                    self._private_key = Ed25519PrivateKey.from_private_bytes(
                        key_bytes
                    )

                except Exception:
                    raise RuntimeError("Invalid SIGNING_PRIVATE_KEY format")

            else:
                # -----------------------------------------
                # 3️⃣ Safe fallback (DEV ONLY)
                # -----------------------------------------
                # Random key (NOT deterministic)
                self._private_key = Ed25519PrivateKey.generate()

        # -----------------------------------------
        # Final setup
        # -----------------------------------------
        self._public_key = self._private_key.public_key()
        self._key_id = self._derive_key_id()

    # ---------------------------------------------------------
    # Signing
    # ---------------------------------------------------------

    def sign(self, message: bytes):
        """
        Returns (signature_hex, key_id)
        """
        signature = self._private_key.sign(message)
        return signature.hex(), self._key_id

    # ---------------------------------------------------------
    # Verification
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