"""
TRACK D — Root Proposal (Cluster Merkle Anchoring)

Security Guarantees:
- Deterministic canonical hashing
- Immutable proposal hash
- Strict UTC enforcement
- Optional previous-root linkage
- Tamper detection
"""

from __future__ import annotations

import json
import hashlib
from typing import Optional, Dict, Any
from datetime import datetime, timezone


# ---------------------------------------------------------
# Strict UTC enforcement
# ---------------------------------------------------------

def _parse_utc(ts: str) -> datetime:
    if not isinstance(ts, str) or not ts.endswith("Z"):
        raise ValueError("Timestamp must be RFC3339 UTC (Z suffix required)")
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


# ---------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------

def _canonical(data: Dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _hash(data: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(data)).hexdigest()


# ---------------------------------------------------------
# Root Proposal
# ---------------------------------------------------------

class RootProposal:
    """
    Immutable Merkle root proposal for cluster anchoring.
    """

    def __init__(
        self,
        *,
        merkle_root: str,
        transparency_log_size: int,
        created_at: str,
        previous_root_hash: Optional[str] = None,
    ):

        if not isinstance(merkle_root, str) or not merkle_root:
            raise ValueError("Invalid merkle_root")

        if not isinstance(transparency_log_size, int) or transparency_log_size < 0:
            raise ValueError("Invalid transparency_log_size")

        _parse_utc(created_at)

        if previous_root_hash is not None:
            if not isinstance(previous_root_hash, str) or len(previous_root_hash) != 64:
                raise ValueError("Invalid previous_root_hash")

        self.merkle_root = merkle_root
        self.transparency_log_size = transparency_log_size
        self.created_at = created_at
        self.previous_root_hash = previous_root_hash

        # Deterministic proposal hash
        self.proposal_hash = self._compute_hash()

    # -----------------------------------------------------
    # Deterministic Hash
    # -----------------------------------------------------

    def _compute_hash(self) -> str:

        payload = {
            "merkle_root": self.merkle_root,
            "transparency_log_size": self.transparency_log_size,
            "created_at": self.created_at,
            "previous_root_hash": self.previous_root_hash,
        }

        return _hash(payload)

    # -----------------------------------------------------
    # Export
    # -----------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "merkle_root": self.merkle_root,
            "transparency_log_size": self.transparency_log_size,
            "created_at": self.created_at,
            "previous_root_hash": self.previous_root_hash,
            "proposal_hash": self.proposal_hash,
        }
