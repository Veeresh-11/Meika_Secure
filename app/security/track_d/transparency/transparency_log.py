"""
TRACK D — Transparency Log (Hardened)

Security Guarantees:
- Append-only semantics
- Deterministic canonical hashing
- Hash-linked entries
- Strict tamper detection
- PASS / FAIL enforcement
- Fail-closed behavior
"""

from __future__ import annotations

import hashlib
import json
from typing import List, Dict, Any, Optional
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


def _canonical(data: Dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _hash_entry(entry: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(entry)).hexdigest()


# ---------------------------------------------------------
# Transparency Log
# ---------------------------------------------------------

class TransparencyLog:

    def __init__(self):
        self._entries: List[Dict[str, Any]] = []

    # ---------------------------------------------------------
    # Append Entry
    # ---------------------------------------------------------

    def append(
        self,
        *,
        payload_hash: str,
        policy_family: Optional[str],
        policy_version: Optional[int],
        result: str,
        timestamp: Optional[str] = None,
    ) -> None:

        # Strict chain validation
        self._validate_chain_or_raise()

        # Structural validation
        if result not in ("PASS", "FAIL"):
            raise ValueError("Invalid result type")

        if not isinstance(payload_hash, str) or len(payload_hash) != 64:
            raise ValueError("Invalid payload_hash")

        previous_hash = (
            self._entries[-1]["entry_hash"]
            if self._entries
            else None
        )

        entry_timestamp = timestamp if timestamp else _utc_now()

        entry = {
            "timestamp": entry_timestamp,
            "payload_hash": payload_hash,
            "policy_family": policy_family,
            "policy_version": policy_version,
            "result": result,
            "previous_hash": previous_hash,
        }

        entry["entry_hash"] = _hash_entry(entry)

        self._entries.append(entry)

    # ---------------------------------------------------------
    # Strict Validation
    # ---------------------------------------------------------

    def _validate_chain_or_raise(self) -> None:

        previous_hash = None

        for entry in self._entries:

            if entry["previous_hash"] != previous_hash:
                raise ValueError("Transparency chain broken")

            entry_copy = dict(entry)
            entry_hash = entry_copy.pop("entry_hash")

            if _hash_entry(entry_copy) != entry_hash:
                raise ValueError("Transparency entry tampered")

            previous_hash = entry_hash

    # ---------------------------------------------------------
    # Public Validation
    # ---------------------------------------------------------

    def validate_chain(self) -> bool:
        self._validate_chain_or_raise()
        return True

    # ---------------------------------------------------------
    # Read-Only View
    # ---------------------------------------------------------

    def entries(self) -> List[Dict[str, Any]]:
        return [dict(e) for e in self._entries]

    def contains(self, payload_hash: str) -> bool:
        return any(entry["payload_hash"] == payload_hash for entry in self._entries)

    def size(self) -> int:
        return len(self._entries)
