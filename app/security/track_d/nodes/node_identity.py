"""
TRACK D — Node Identity (Final Stabilized)

Security Guarantees:
- Deterministic node_id = SHA256(public_key)
- Strict UTC lifecycle validation
- Capability validation
- Weight enforcement
- Consensus vote signing + verification
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import List, Optional, Set

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


VALID_CAPABILITIES = {"VERIFY", "ANCHOR", "CONSENSUS"}


# ---------------------------------------------------------
# Strict UTC Parsing
# ---------------------------------------------------------

def _parse_utc(ts: str) -> datetime:
    if not isinstance(ts, str) or not ts.endswith("Z"):
        raise ValueError("Timestamp must be RFC3339 UTC (Z suffix required)")
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


# ---------------------------------------------------------
# Vote Model
# ---------------------------------------------------------

class Vote:

    def __init__(self, *, node_id: str, proposal_hash: str, signature: str):
        self.node_id = node_id
        self.proposal_hash = proposal_hash
        self.signature = signature

    def verify(self, public_key_bytes: bytes) -> bool:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        try:
            public_key.verify(
                bytes.fromhex(self.signature),
                self.proposal_hash.encode(),
            )
            return True
        except Exception:
            return False


# ---------------------------------------------------------
# Node Identity
# ---------------------------------------------------------

class NodeIdentity:

    def __init__(
        self,
        *,
        public_key: bytes,
        created_at: str,
        capabilities: List[str],
        weight: int,
        expires_at: Optional[str] = None,
        revoked_at: Optional[str] = None,
        private_key: Optional[Ed25519PrivateKey] = None,
    ):

        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise ValueError("Invalid public key")

        if weight <= 0:
            raise ValueError("Weight must be positive")

        for cap in capabilities:
            if cap not in VALID_CAPABILITIES:
                raise ValueError("Invalid capability")

        created_dt = _parse_utc(created_at)

        if expires_at:
            if _parse_utc(expires_at) <= created_dt:
                raise ValueError("Expiry before creation")

        if revoked_at:
            if _parse_utc(revoked_at) <= created_dt:
                raise ValueError("Revocation before creation")

        self.public_key_bytes = public_key
        self.private_key = private_key
        self.created_at = created_at
        self.expires_at = expires_at
        self.revoked_at = revoked_at
        self.capabilities: Set[str] = set(capabilities)
        self.weight = weight

        self.node_id = hashlib.sha256(public_key).hexdigest()

    # -----------------------------------------------------
    # Factory Generator (Consensus Mode)
    # -----------------------------------------------------

    @classmethod
    def generate(
        cls,
        *,
        weight: int,
        capabilities: Optional[List[str]] = None,
    ) -> "NodeIdentity":

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes_raw()

        return cls(
            public_key=public_key,
            created_at="2026-01-01T00:00:00Z",
            capabilities=capabilities or ["CONSENSUS"],
            weight=weight,
            private_key=private_key,
        )

    # -----------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------

    def is_active(self, at_timestamp: str) -> bool:
        at_dt = _parse_utc(at_timestamp)

        if at_dt < _parse_utc(self.created_at):
            return False

        if self.revoked_at and at_dt >= _parse_utc(self.revoked_at):
            return False

        if self.expires_at and at_dt >= _parse_utc(self.expires_at):
            return False

        return True

    def validate_active(self, at_timestamp: str) -> None:
        if not self.is_active(at_timestamp):
            raise ValueError("Node not active")

    # -----------------------------------------------------
    # Consensus Vote Signing
    # -----------------------------------------------------

    def sign_vote(self, proposal_hash: str) -> Vote:

        if not self.private_key:
            raise ValueError("Node has no signing capability")

        signature = self.private_key.sign(proposal_hash.encode())

        return Vote(
            node_id=self.node_id,
            proposal_hash=proposal_hash,
            signature=signature.hex(),
        )
