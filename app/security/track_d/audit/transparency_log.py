"""
TRACK D — Transparency Log (Merkle-Based Public Proof Layer)

Guarantees:
- Append-only log
- Deterministic hashing
- Merkle root calculation
- Inclusion proof generation
- Tamper detection
"""

from __future__ import annotations

import hashlib
import json
from typing import List, Dict


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(entry: Dict) -> bytes:
    return json.dumps(
        entry,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class TransparencyLog:

    def __init__(self):
        self._entries: List[Dict] = []
        self._leaf_hashes: List[str] = []

    # -------------------------------------------------
    # Append Entry
    # -------------------------------------------------

    def append(self, entry: Dict) -> str:
        """
        Append a new entry to the transparency log.
        Returns the Merkle root after insertion.
        """

        canonical = _canonical(entry)
        leaf_hash = _hash(canonical)

        self._entries.append(entry)
        self._leaf_hashes.append(leaf_hash)

        return self.get_root()

    # -------------------------------------------------
    # Merkle Root
    # -------------------------------------------------

    def get_root(self) -> str:
        if not self._leaf_hashes:
            return _hash(b"")

        return self._build_merkle_root(self._leaf_hashes)

    def _build_merkle_root(self, leaves: List[str]) -> str:
        current = leaves.copy()

        while len(current) > 1:
            next_level = []

            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else left

                combined = (left + right).encode("utf-8")
                next_level.append(_hash(combined))

            current = next_level

        return current[0]

    # -------------------------------------------------
    # Inclusion Proof
    # -------------------------------------------------

    def get_inclusion_proof(self, index: int) -> List[str]:
        """
        Returns the Merkle proof path for a given leaf index.
        """

        if index < 0 or index >= len(self._leaf_hashes):
            raise ValueError("Invalid index")

        proof = []
        level = self._leaf_hashes.copy()
        idx = index

        while len(level) > 1:
            next_level = []

            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left

                combined = _hash((left + right).encode("utf-8"))
                next_level.append(combined)

                if i == idx or i + 1 == idx:
                    sibling = right if i == idx else left
                    proof.append(sibling)
                    idx = len(next_level) - 1

            level = next_level

        return proof

    # -------------------------------------------------
    # Tamper Detection
    # -------------------------------------------------

    def validate(self) -> bool:
        recalculated = []

        for entry in self._entries:
            recalculated.append(_hash(_canonical(entry)))

        return recalculated == self._leaf_hashes
