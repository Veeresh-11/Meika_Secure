"""
TRACK D — Signer Interface (Constitutional Hardened)

Defines strict contract for all signing implementations.

Security Guarantees:
- Deterministic signature interface
- Explicit byte-level signing
- No implicit hashing
- Hardware-awareness capability
- No redundant key return values
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class ISigner(ABC):
    """
    Constitutional signing interface.

    Implementations MUST:
    - Sign raw bytes deterministically
    - NOT perform implicit hashing
    - NOT modify input data
    """

    # ---------------------------------------------------------
    # Signing
    # ---------------------------------------------------------

    @abstractmethod
    def sign(self, message: bytes) -> str:
        """
        Sign raw bytes.

        MUST:
            - Sign exactly the provided bytes
            - Return signature as hex string
            - Be deterministic (Ed25519 or equivalent)

        Returns:
            signature_hex: str
        """
        raise NotImplementedError

    # ---------------------------------------------------------
    # Metadata
    # ---------------------------------------------------------

    @abstractmethod
    def algorithm(self) -> str:
        """
        Return algorithm identifier (e.g., "Ed25519").
        """
        raise NotImplementedError

    @abstractmethod
    def key_id(self) -> str:
        """
        Return logical key identifier.
        """
        raise NotImplementedError

    @abstractmethod
    def public_key_hex(self) -> str:
        """
        Return public key as hex string.
        """
        raise NotImplementedError

    @abstractmethod
    def is_hardware(self) -> bool:
        """
        Return True if signer is hardware-backed.
        """
        raise NotImplementedError
