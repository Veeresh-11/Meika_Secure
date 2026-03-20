"""
TRACK D — Signing Key Registry (Hardened)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional
from datetime import datetime, timezone

from .signer_interface import ISigner


# ---------------------------------------------------------
# Strict UTC Parsing
# ---------------------------------------------------------

def _parse_utc(ts: str) -> datetime:
    if not isinstance(ts, str) or not ts.endswith("Z"):
        raise ValueError("Timestamp must be RFC3339 UTC (Z suffix required)")
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def _utc_now() -> datetime:
    return datetime.utcnow().replace(tzinfo=timezone.utc)


# ---------------------------------------------------------
# Status Model
# ---------------------------------------------------------

class SigningKeyStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    REVOKED = "REVOKED"


@dataclass(frozen=True)
class SigningKeyMetadata:
    key_id: str
    algorithm: str
    created_at: datetime
    expires_at: Optional[datetime]
    revoked_at: Optional[datetime]
    status: SigningKeyStatus
    signer: ISigner


# ---------------------------------------------------------
# Registry
# ---------------------------------------------------------

class KeyRegistry:

    def __init__(self) -> None:
        self._keys: Dict[str, SigningKeyMetadata] = {}

    # -----------------------------------------------------
    # Registration
    # -----------------------------------------------------

    def register_key(
        self,
        *,
        key_id: str,
        algorithm: str,
        created_at: str,
        signer: ISigner,
        make_active: bool = False,
        expires_at: Optional[str] = None,
    ) -> None:

        if key_id in self._keys:
            raise ValueError("Key ID already exists")

        if signer.algorithm() != algorithm:
            raise ValueError("Algorithm mismatch with signer")

        created = _parse_utc(created_at)
        expires = _parse_utc(expires_at) if expires_at else None

        if expires and expires <= created:
            raise ValueError("expires_at must be after created_at")

        status = SigningKeyStatus.ACTIVE if make_active else SigningKeyStatus.DEPRECATED

        if make_active:
            self._deactivate_existing_active()

        self._keys[key_id] = SigningKeyMetadata(
            key_id=key_id,
            algorithm=algorithm,
            created_at=created,
            expires_at=expires,
            revoked_at=None,
            status=status,
            signer=signer,
        )

    # -----------------------------------------------------
    # Rotation
    # -----------------------------------------------------

    def rotate(
        self,
        *,
        key_id: str,
        algorithm: str,
        created_at: str,
        signer: ISigner,
        expires_at: Optional[str] = None,
    ) -> None:

        self._deactivate_existing_active()

        self.register_key(
            key_id=key_id,
            algorithm=algorithm,
            created_at=created_at,
            signer=signer,
            make_active=True,
            expires_at=expires_at,
        )

    # -----------------------------------------------------
    # Revocation
    # -----------------------------------------------------

    def revoke(self, key_id: str, revoked_at: Optional[str] = None) -> None:

        if key_id not in self._keys:
            raise ValueError("Unknown key_id")

        meta = self._keys[key_id]

        if meta.status == SigningKeyStatus.REVOKED:
            raise ValueError("Key already revoked")

        revoked = _parse_utc(revoked_at) if revoked_at else _utc_now()

        if revoked < meta.created_at:
            raise ValueError("Revocation cannot precede creation")

        self._keys[key_id] = SigningKeyMetadata(
            key_id=meta.key_id,
            algorithm=meta.algorithm,
            created_at=meta.created_at,
            expires_at=meta.expires_at,
            revoked_at=revoked,
            status=SigningKeyStatus.REVOKED,
            signer=meta.signer,
        )

    # -----------------------------------------------------
    # Retrieval
    # -----------------------------------------------------

    def get_active(self) -> SigningKeyMetadata:

        active = [
            k for k in self._keys.values()
            if k.status == SigningKeyStatus.ACTIVE
        ]

        if len(active) != 1:
            raise ValueError("Exactly one ACTIVE key required")

        meta = active[0]

        if meta.expires_at and meta.expires_at <= _utc_now():
            raise ValueError("Active key expired")

        return meta

    # 🔥 RESTORED FOR TEST COMPATIBILITY
    def get_active_signer(self) -> SigningKeyMetadata:
        return self.get_active()

    def get(self, key_id: str) -> SigningKeyMetadata:
        if key_id not in self._keys:
            raise ValueError("Unknown key_id")
        return self._keys[key_id]

    # -----------------------------------------------------
    # Integrity Check
    # -----------------------------------------------------

    def validate_integrity(self) -> bool:
        active_count = sum(
            1 for k in self._keys.values()
            if k.status == SigningKeyStatus.ACTIVE
        )
        return active_count <= 1

    # -----------------------------------------------------
    # Internal
    # -----------------------------------------------------

    def _deactivate_existing_active(self) -> None:
        for key_id, meta in list(self._keys.items()):
            if meta.status == SigningKeyStatus.ACTIVE:
                self._keys[key_id] = SigningKeyMetadata(
                    key_id=meta.key_id,
                    algorithm=meta.algorithm,
                    created_at=meta.created_at,
                    expires_at=meta.expires_at,
                    revoked_at=meta.revoked_at,
                    status=SigningKeyStatus.DEPRECATED,
                    signer=meta.signer,
                )
