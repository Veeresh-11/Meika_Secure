"""
TRACK D — Gossip Verifier

Security Guarantees:
- Detects forks
- Detects history rewrites
- Detects truncation attacks
- Detects inconsistent anchors
"""

from __future__ import annotations
from typing import List, Dict, Any

from ..anchoring.root_anchor_ledger import RootAnchorLedger


class GossipVerifier:

    def __init__(self, local_ledger: RootAnchorLedger):
        self.local_ledger = local_ledger

    def verify_remote_chain(
        self,
        remote_entries: List[Dict[str, Any]],
    ) -> bool:

        # Validate local first
        self.local_ledger.validate_chain()

        local_entries = self.local_ledger.snapshot()

        # Case 1: identical
        if remote_entries == local_entries:
            return True

        # Case 2: remote extends local
        if len(remote_entries) >= len(local_entries):
            for i in range(len(local_entries)):
                if remote_entries[i] != local_entries[i]:
                    raise ValueError("Fork detected: divergence in prefix")

            return True

        # Case 3: remote shorter (possible truncation)
        if len(remote_entries) < len(local_entries):
            for i in range(len(remote_entries)):
                if remote_entries[i] != local_entries[i]:
                    raise ValueError("Fork detected: divergence")

            raise ValueError("Remote chain truncated")

        raise ValueError("Unknown inconsistency")
