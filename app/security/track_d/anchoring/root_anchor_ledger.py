"""
TRACK D — Root Anchor Ledger
Sovereign Root Chain (Constitutional Grade — Policy Bound)

Security Guarantees:
- Append-only ledger
- Deterministic hashing
- Fork detection
- Tamper detection
- Genesis protection
- Anchor policy enforcement
- Multi-network anchor binding
- Policy hash binding (governance immutability)
"""

from __future__ import annotations

import json
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from .anchor_receipt import AnchorReceipt
from .anchor_policy_engine import AnchorPolicyEngine


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

def _canonical(obj: Dict[str, Any]) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _hash(obj: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(obj)).hexdigest()


# ---------------------------------------------------------
# Root Anchor Ledger
# ---------------------------------------------------------

class RootAnchorLedger:
    """
    Sovereign root anchor ledger with constitutional enforcement.

    Each entry binds:
    - certificate hash
    - anchor receipts
    - anchor policy version
    - anchor policy hash (governance binding)
    - previous entry hash
    - deterministic entry hash
    """

    def __init__(self, policy_engine: AnchorPolicyEngine):
        self._entries: List[Dict[str, Any]] = []
        self._policy_engine = policy_engine

    # -----------------------------------------------------
    # Append Root Certificate (with anchor receipts)
    # -----------------------------------------------------

    def append(
        self,
        *,
        certificate_hash: str,
        anchored_at: str,
        receipts: List[AnchorReceipt],
    ) -> None:

        if not isinstance(certificate_hash, str) or len(certificate_hash) != 64:
            raise ValueError("Invalid certificate hash")

        if not receipts:
            raise ValueError("Anchor receipts required")

        anchored_dt = _parse_utc(anchored_at)

        # Enforce anchor policy
        if not self._policy_engine.evaluate(receipts):
            raise ValueError("Anchor policy violation")

        # Verify receipt integrity
        for receipt in receipts:
            receipt.verify_integrity()

        previous_hash: Optional[str] = None

        if self._entries:
            previous_hash = self._entries[-1]["entry_hash"]

            prev_time = _parse_utc(self._entries[-1]["anchored_at"])
            if anchored_dt <= prev_time:
                raise ValueError("Anchoring timestamp must increase")

        policy = self._policy_engine.policy

        entry = {
            "previous_entry_hash": previous_hash,
            "certificate_hash": certificate_hash,
            "anchored_at": anchored_at,
            "policy_version": policy.version,
            "policy_hash": policy.policy_hash,
            "networks": sorted([r.network for r in receipts]),
            "receipts": [r.to_dict() for r in receipts],
        }

        entry["entry_hash"] = _hash(entry)

        self._entries.append(entry)

    # -----------------------------------------------------
    # Latest Entry
    # -----------------------------------------------------

    def latest(self) -> Optional[Dict[str, Any]]:
        return dict(self._entries[-1]) if self._entries else None

    # -----------------------------------------------------
    # Validate Chain
    # -----------------------------------------------------

    def validate_chain(self) -> bool:

        previous_hash = None

        for entry in self._entries:

            entry_copy = dict(entry)
            entry_hash = entry_copy.pop("entry_hash")

            # Deterministic hash validation
            if _hash(entry_copy) != entry_hash:
                raise ValueError("Root ledger tampering detected")

            # Fork detection
            if entry["previous_entry_hash"] != previous_hash:
                raise ValueError("Root chain fork detected")

            # Governance binding validation
            if entry["policy_hash"] != self._policy_engine.policy.policy_hash:
                raise ValueError("Policy hash mismatch detected")

            previous_hash = entry_hash

        return True

    # -----------------------------------------------------
    # Export Snapshot
    # -----------------------------------------------------

    def snapshot(self) -> List[Dict[str, Any]]:
        return [dict(e) for e in self._entries]
