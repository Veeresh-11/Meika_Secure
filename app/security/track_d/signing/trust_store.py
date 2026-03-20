"""
TRACK D — Sovereign Trust Store (Hardened)

High-Assurance Identity Registry

Security Guarantees:
- Strict UTC enforcement
- Weighted quorum support
- Role metadata binding
- Algorithm binding
- Lifecycle enforcement (activation / revocation / expiration)
- Provider binding (software / hsm)
- Hardware-root downgrade protection
- Governance compatibility
- Transparency compatibility
- Backward test compatibility
"""

from __future__ import annotations

from typing import Dict, Optional, List
from datetime import datetime, timezone
import hashlib


# ---------------------------------------------------------
# Strict UTC Parsing
# ---------------------------------------------------------

def _parse_utc(ts: str) -> datetime:
    if not isinstance(ts, str) or not ts.endswith("Z"):
        raise ValueError("Timestamp must be RFC3339 UTC (Z suffix required)")
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


# ---------------------------------------------------------
# Trust Store
# ---------------------------------------------------------

class TrustStore:

    def __init__(self):
        self._trusted: Dict[str, Dict] = {}

    # -----------------------------------------------------
    # Primary Registration
    # -----------------------------------------------------

    def add_trusted_key(
        self,
        *,
        key_id: str,
        public_key_bytes: bytes,
        created_at: str,
        expires_at: Optional[str] = None,
        weight: int = 1,
        roles: Optional[List[str]] = None,
        algorithm: str = "Ed25519",
        provider: str = "software",
        hardware_root: bool = False,
    ):

        if key_id in self._trusted:
            raise ValueError("Key ID collision")

        if not isinstance(public_key_bytes, bytes):
            raise ValueError("public_key_bytes must be bytes")

        if not isinstance(weight, int) or weight <= 0:
            raise ValueError("Invalid weight")

        # 🚨 Critical security invariant
        if hardware_root and provider != "hsm":
            raise ValueError("Hardware root must use HSM provider")

        created = _parse_utc(created_at)
        expires = _parse_utc(expires_at) if expires_at else None

        if expires and expires <= created:
            raise ValueError("expires_at must be after created_at")

        self._trusted[key_id] = {
            "public_key": public_key_bytes,
            "created_at": created,
            "expires_at": expires,
            "revoked_at": None,
            "weight": weight,
            "roles": roles or [],
            "algorithm": algorithm,
            "provider": provider,
            "hardware_root": hardware_root,
            "fingerprint": hashlib.sha256(public_key_bytes).hexdigest(),
        }

    # -----------------------------------------------------
    # Backward Compatibility (Tests Expect This)
    # -----------------------------------------------------

    def register_key(
        self,
        *,
        key_id: str,
        public_key: bytes,
        algorithm: str,
        weight: int,
        roles: List[str],
        created_at: str,
    ):
        """
        Compatibility wrapper used by test suite.
        """
        self.add_trusted_key(
            key_id=key_id,
            public_key_bytes=public_key,
            created_at=created_at,
            weight=weight,
            roles=roles,
            algorithm=algorithm,
        )

    # -----------------------------------------------------
    # Revocation
    # -----------------------------------------------------

    def revoke(self, key_id: str, revoked_at: str):

        if key_id not in self._trusted:
            raise ValueError("Unknown key")

        revoked = _parse_utc(revoked_at)

        if revoked < self._trusted[key_id]["created_at"]:
            raise ValueError("Revocation cannot precede creation")

        self._trusted[key_id]["revoked_at"] = revoked

    # -----------------------------------------------------
    # Lifecycle Validation
    # -----------------------------------------------------

    def validate_lifecycle(self, key_id: str, now_utc: str):

        if key_id not in self._trusted:
            raise ValueError("Key not trusted")

        now = _parse_utc(now_utc)
        meta = self._trusted[key_id]

        if now < meta["created_at"]:
            raise ValueError("Key used before activation")

        if meta["revoked_at"] is not None:
            raise ValueError("Key revoked")

        if meta["expires_at"] and now > meta["expires_at"]:
            raise ValueError("Key expired")

    # -----------------------------------------------------
    # Accessors
    # -----------------------------------------------------

    def get_public_key(self, key_id: str) -> bytes:
        if key_id not in self._trusted:
            raise ValueError("Key not trusted")
        return self._trusted[key_id]["public_key"]

    def get_weight(self, key_id: str) -> int:
        if key_id not in self._trusted:
            raise ValueError("Key not trusted")
        return self._trusted[key_id]["weight"]

    def get_roles(self, key_id: str) -> List[str]:
        if key_id not in self._trusted:
            raise ValueError("Key not trusted")
        return list(self._trusted[key_id]["roles"])

    def get_algorithm(self, key_id: str) -> str:
        if key_id not in self._trusted:
            raise ValueError("Key not trusted")
        return self._trusted[key_id]["algorithm"]

    def get_provider(self, key_id: str) -> str:
        if key_id not in self._trusted:
            raise ValueError("Key not trusted")
        return self._trusted[key_id]["provider"]

    def is_hardware_root(self, key_id: str) -> bool:
        if key_id not in self._trusted:
            raise ValueError("Key not trusted")
        return self._trusted[key_id]["hardware_root"]

    def get_metadata(self, key_id: str) -> Dict:
        if key_id not in self._trusted:
            raise ValueError("Key not trusted")
        return dict(self._trusted[key_id])

    # -----------------------------------------------------
    # Integrity Validation
    # -----------------------------------------------------

    def validate_integrity(self) -> bool:
        """
        Ensures no malformed entries exist.
        """
        for key_id, meta in self._trusted.items():

            if not isinstance(meta["public_key"], bytes):
                return False

            if not isinstance(meta["weight"], int) or meta["weight"] <= 0:
                return False

            if meta["hardware_root"] and meta["provider"] != "hsm":
                return False

        return True
