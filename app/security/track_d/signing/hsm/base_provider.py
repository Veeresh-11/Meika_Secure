"""
TRACK D — HSM Provider Base Interface (Hardened)

Security Contract:

All providers MUST:

- Fail closed (never fallback silently)
- Perform deterministic signing
- Raise on unknown key_id
- Never auto-generate keys during sign()
- Never mutate internal state during sign()
- Return raw signature bytes
- Clearly signal hardware vs software backing

This interface defines the cryptographic boundary
between TrustStore and signing execution.
"""

from __future__ import annotations
from abc import ABC, abstractmethod


class HSMProvider(ABC):
    """
    Abstract HSM Provider Interface.

    Providers MUST:
    - Implement deterministic sign()
    - Raise ValueError for unknown key_id
    - Never fallback to software silently
    """

    # ---------------------------------------------------------
    # Signing
    # ---------------------------------------------------------

    @abstractmethod
    def sign(self, key_id: str, message: bytes) -> bytes:
        """
        Deterministically sign message using key_id.

        Requirements:
        - Must raise ValueError if key_id not found
        - Must raise if provider not initialized
        - Must NOT mutate provider state
        - Must NOT auto-generate keys
        - Must return raw signature bytes
        """
        raise NotImplementedError

    # ---------------------------------------------------------
    # Public Key Retrieval
    # ---------------------------------------------------------

    @abstractmethod
    def get_public_key(self, key_id: str) -> bytes:
        """
        Return raw public key bytes.

        Requirements:
        - Must raise ValueError if key_id not found
        - Must NOT fallback
        - Must be deterministic
        """
        raise NotImplementedError

    # ---------------------------------------------------------
    # Provider Identity
    # ---------------------------------------------------------

    @abstractmethod
    def is_hardware(self) -> bool:
        """
        Return True if this provider is backed by real hardware.
        """
        raise NotImplementedError
