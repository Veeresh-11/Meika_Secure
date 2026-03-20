"""
TRACK D — Governance Registry (Hardened Constitutional Layer)

Security Guarantees:
- Strict UTC enforcement
- Monotonic version enforcement
- Backdating protection
- Tamper detection via entry hashing
- Immutable policy retrieval
- Family sealing enforcement
- Policy expiration support
"""

from __future__ import annotations

import json
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone


# ---------------------------------------------------------
# Strict UTC
# ---------------------------------------------------------

def _parse_utc(ts: str) -> datetime:
    if not isinstance(ts, str) or not ts.endswith("Z"):
        raise ValueError("Timestamp must be RFC3339 UTC (Z suffix required)")
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


# ---------------------------------------------------------
# Canonical Hashing
# ---------------------------------------------------------

def _canonical(entry: Dict[str, Any]) -> bytes:
    return json.dumps(
        entry,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _hash(entry: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(entry)).hexdigest()


# ---------------------------------------------------------
# Governance Registry
# ---------------------------------------------------------

class GovernanceRegistry:

    def __init__(self):
        self._families: Dict[str, List[Dict[str, Any]]] = {}
        self._sealed: set[str] = set()

    # ---------------------------------------------------------
    # Add Policy
    # ---------------------------------------------------------

    def add_policy(
        self,
        *,
        policy_family: str,
        version: int,
        effective_from: str,
        minimum_weight: int,
        required_roles: Optional[List[str]] = None,
        hardware_root_required: bool = False,
    ) -> None:

        if not isinstance(version, int) or version <= 0:
            raise ValueError("Invalid version")

        if not isinstance(minimum_weight, int) or minimum_weight <= 0:
            raise ValueError("Invalid minimum_weight")

        if policy_family in self._sealed:
            raise ValueError("Policy family is sealed")

        effective_dt = _parse_utc(effective_from)

        family = self._families.setdefault(policy_family, [])

        # Enforce monotonic versioning + backdating protection
        if family:
            latest = family[-1]

            if version <= latest["version"]:
                raise ValueError("Version must increase monotonically")

            latest_dt = _parse_utc(latest["effective_from"])
            if effective_dt <= latest_dt:
                raise ValueError("Backdating rejected")

        policy = {
            "policy_family": policy_family,
            "version": version,
            "effective_from": effective_from,
            "minimum_weight": minimum_weight,
            "required_roles": list(required_roles or []),
            "hardware_root_required": bool(hardware_root_required),
            "expires_at": None,
        }

        policy["entry_hash"] = _hash(policy)

        family.append(policy)

    # ---------------------------------------------------------
    # Expire Policy
    # ---------------------------------------------------------

    def expire_policy(
        self,
        policy_family: str,
        version: int,
        expires_at: str,
    ) -> None:

        _parse_utc(expires_at)

        policy = self.get_policy(policy_family, version)

        if policy["expires_at"] is not None:
            raise ValueError("Policy already expired")

        policy["expires_at"] = expires_at

        # Re-hash entry after mutation
        entry_copy = dict(policy)
        entry_copy.pop("entry_hash", None)
        policy["entry_hash"] = _hash(entry_copy)

    # ---------------------------------------------------------
    # Seal Family
    # ---------------------------------------------------------

    def seal_family(self, policy_family: str) -> None:

        if policy_family not in self._families:
            raise ValueError("Cannot seal unknown family")

        self._sealed.add(policy_family)

    # ---------------------------------------------------------
    # Chain Validation
    # ---------------------------------------------------------

    def validate_chain(self, policy_family: str) -> bool:

        family = self._families.get(policy_family, [])

        previous_version = 0

        for policy in family:

            entry_copy = dict(policy)
            entry_hash = entry_copy.pop("entry_hash")

            if _hash(entry_copy) != entry_hash:
                raise ValueError("Governance tampering detected")

            if policy["version"] <= previous_version:
                raise ValueError("Version ordering violation")

            previous_version = policy["version"]

        return True

    # ---------------------------------------------------------
    # Direct Policy Lookup (Used by Verifier)
    # ---------------------------------------------------------

    def get_policy(
        self,
        policy_family: str,
        version: int,
    ) -> Dict[str, Any]:

        self.validate_chain(policy_family)

        family = self._families.get(policy_family, [])

        for policy in family:
            if policy["version"] == version:
                return policy

        raise ValueError("Policy not found")

    # ---------------------------------------------------------
    # Get Active Policy (Time-Aware)
    # ---------------------------------------------------------

    def get_active_policy(
        self,
        *,
        policy_family: str,
        at_timestamp: str,
    ) -> Optional[Dict[str, Any]]:

        self.validate_chain(policy_family)

        at_dt = _parse_utc(at_timestamp)

        family = self._families.get(policy_family, [])

        active = None

        for policy in family:
            policy_dt = _parse_utc(policy["effective_from"])
            if policy_dt <= at_dt:
                active = policy

        return dict(active) if active else None

    # ---------------------------------------------------------
    # Latest Policy
    # ---------------------------------------------------------

    def get_latest_policy(self, policy_family: str) -> Optional[Dict[str, Any]]:

        self.validate_chain(policy_family)

        family = self._families.get(policy_family, [])

        return dict(family[-1]) if family else None
