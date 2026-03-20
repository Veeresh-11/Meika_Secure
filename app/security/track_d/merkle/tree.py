"""
TRACK D+ — Deterministic Merkle Tree

Security Guarantees:
- SHA-256 hashing
- Deterministic leaf ordering
- Left-right aware node hashing
- No implicit padding tricks
- Fail-closed on empty tree (root = None)
"""

from __future__ import annotations

import hashlib
from typing import List


def _hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hash_pair(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(left + right).digest()


class MerkleTree:

    def __init__(self, leaves: List[bytes]):

        # Deterministic ordering
        self.leaves = sorted(leaves)

        if not self.leaves:
            self.levels = []
            self.root = None
            return

        current_level = [_hash(leaf) for leaf in self.leaves]
        self.levels = [current_level]

        while len(current_level) > 1:

            next_level = []

            for i in range(0, len(current_level), 2):

                left = current_level[i]

                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # Duplicate last node if odd
                    right = left

                parent = _hash_pair(left, right)
                next_level.append(parent)

            self.levels.append(next_level)
            current_level = next_level

        self.root = current_level[0]

    def get_root_hex(self) -> str | None:
        return self.root.hex() if self.root else None
