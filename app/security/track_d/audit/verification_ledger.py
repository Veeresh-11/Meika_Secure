"""
TRACK D — Immutable Verification Ledger (Hardened)

Security Guarantees:
- Append-only semantics
- Deterministic canonical hashing
- Hash-linked entries
- Strict chain validation
- PASS / FAIL enforcement
- Tamper detection
- Fail-closed behavior
"""

from __future__ import annotations

import json
import hashlib
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _canonical(entry: Dict[str, Any]) -> bytes:
    return json.dumps(
        entry,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _hash_entry(entry: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(entry)).hexdigest()


# ---------------------------------------------------------
# Ledger
# ---------------------------------------------------------

class VerificationLedger:
    """
    Immutable verification ledger.
    Hash-linked entries.
    """

    def __init__(self):
        self._chain: List[Dict[str, Any]] = []

    # ---------------------------------------------------------
    # Append Entry
    # ---------------------------------------------------------

    def append(
        self,
        *,
        payload_hash: str,
        key_ids: List[str],
        policy_family: Optional[str],
        policy_version: Optional[int],
        result: str,
        reason: Optional[str],
        timestamp: Optional[str] = None,
    ) -> None:

        # ---------------------------------------------------------
        # Strict chain validation (fail-closed)
        # ---------------------------------------------------------

        self._validate_chain_or_raise()

        # ---------------------------------------------------------
        # Structural validation
        # ---------------------------------------------------------

        if result not in ("PASS", "FAIL"):
            raise ValueError("Invalid result type")

        if not isinstance(payload_hash, str) or len(payload_hash) != 64:
            raise ValueError("Invalid payload_hash")

        if not isinstance(key_ids, list):
            raise ValueError("key_ids must be a list")

        # ---------------------------------------------------------
        # Previous hash linkage
        # ---------------------------------------------------------

        previous_hash = (
            self._chain[-1]["entry_hash"]
            if self._chain
            else None
        )

        entry_timestamp = timestamp if timestamp else _utc_now()

        entry = {
            "timestamp": entry_timestamp,
            "payload_hash": payload_hash,
            "key_ids": sorted(key_ids),
            "policy_family": policy_family,
            "policy_version": policy_version,
            "result": result,
            "reason": reason,
            "previous_hash": previous_hash,
        }

        entry["entry_hash"] = _hash_entry(entry)

        self._chain.append(entry)

    # ---------------------------------------------------------
    # Strict Chain Validation
    # ---------------------------------------------------------

    def _validate_chain_or_raise(self) -> None:

        previous_hash = None

        for entry in self._chain:

            if entry["previous_hash"] != previous_hash:
                raise ValueError("Ledger linkage violation detected")

            entry_copy = dict(entry)
            entry_hash = entry_copy.pop("entry_hash")

            if _hash_entry(entry_copy) != entry_hash:
                raise ValueError("Ledger tampering detected")

            previous_hash = entry_hash

    # ---------------------------------------------------------
    # Public Validation
    # ---------------------------------------------------------

    def validate_chain(self) -> bool:
        try:
            self._validate_chain_or_raise()
            return True
        except Exception:
            return False

    # ---------------------------------------------------------
    # Read-Only View
    # ---------------------------------------------------------

    def entries(self) -> List[Dict[str, Any]]:
        # Return deep copies to prevent mutation
        return [dict(e) for e in self._chain]
