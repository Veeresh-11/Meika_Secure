"""
TRACK D — Gossip Consistency Proof

Provides minimal proof to verify that:
- A remote root chain extends ours
- No fork occurred
- No history rewrite happened
"""

from __future__ import annotations
from typing import List, Dict, Any


class ConsistencyProof:

    def __init__(self, entries: List[Dict[str, Any]]):
        self.entries = entries

    def first_hash(self) -> str | None:
        if not self.entries:
            return None
        return self.entries[0]["entry_hash"]

    def last_hash(self) -> str | None:
        if not self.entries:
            return None
        return self.entries[-1]["entry_hash"]

    def length(self) -> int:
        return len(self.entries)
