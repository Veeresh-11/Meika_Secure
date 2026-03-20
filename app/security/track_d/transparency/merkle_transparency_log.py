"""
TRACK D — Enterprise Merkle Transparency Log (Constitutional Grade)

Security Guarantees:
- Append-only
- Deterministic SHA-256 Merkle tree
- Leaf immutability
- Structural validation
- Inclusion proof support
- Root recomputation verification
- Sealable log
- Fail-closed behavior
"""

from __future__ import annotations

import hashlib
import json
from typing import List, Dict, Any, Optional, Tuple
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


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hash_leaf(entry: Dict[str, Any]) -> bytes:
    return _sha256(_canonical(entry))


def _hash_pair(left: bytes, right: bytes) -> bytes:
    return _sha256(left + right)


def _build_merkle_tree(leaves: List[bytes]) -> List[List[bytes]]:

    if not leaves:
        return []

    tree = [leaves]
    current = leaves

    while len(current) > 1:
        next_level = []

        for i in range(0, len(current), 2):
            left = current[i]

            if i + 1 < len(current):
                right = current[i + 1]
            else:
                right = left

            next_level.append(_hash_pair(left, right))

        tree.append(next_level)
        current = next_level

    return tree


# ---------------------------------------------------------
# Merkle Transparency Log
# ---------------------------------------------------------

class MerkleTransparencyLog:

    def __init__(self):
        self._entries: List[Dict[str, Any]] = []
        self._leaf_hashes: List[bytes] = []
        self._sealed = False

    # ---------------------------------------------------------
    # Append
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

        if self._sealed:
            raise ValueError("Transparency log is sealed")

        # Validate existing integrity
        if not self.validate_integrity():
            raise ValueError("Merkle log integrity violation")

        # Structural validation
        if result not in ("PASS", "FAIL"):
            raise ValueError("Invalid result value")

        if not isinstance(payload_hash, str) or len(payload_hash) != 64:
            raise ValueError("Invalid payload_hash")

        entry = {
            "timestamp": timestamp or _utc_now(),
            "payload_hash": payload_hash,
            "policy_family": policy_family,
            "policy_version": policy_version,
            "result": result,
        }

        leaf_hash = _hash_leaf(entry)

        self._entries.append(dict(entry))
        self._leaf_hashes.append(leaf_hash)

    # ---------------------------------------------------------
    # Root
    # ---------------------------------------------------------

    def merkle_root(self) -> Optional[str]:

        if not self._leaf_hashes:
            return None

        tree = _build_merkle_tree(self._leaf_hashes)
        return tree[-1][0].hex()

    # ---------------------------------------------------------
    # Inclusion Proof
    # ---------------------------------------------------------

    def get_inclusion_proof(self, index: int) -> List[Tuple[str, str]]:

        if index < 0 or index >= len(self._leaf_hashes):
            raise ValueError("Invalid index")

        tree = _build_merkle_tree(self._leaf_hashes)

        proof = []
        idx = index

        for level in tree[:-1]:

            if idx % 2 == 0:
                sibling_index = idx + 1
                direction = "right"
            else:
                sibling_index = idx - 1
                direction = "left"

            if sibling_index >= len(level):
                sibling_hash = level[idx]
            else:
                sibling_hash = level[sibling_index]

            proof.append((direction, sibling_hash.hex()))
            idx //= 2

        return proof

    # ---------------------------------------------------------
    # Inclusion Verification
    # ---------------------------------------------------------

    @staticmethod
    def verify_inclusion_proof(
        entry: Dict[str, Any],
        proof: List[Tuple[str, str]],
        expected_root_hex: str,
    ) -> bool:

        current_hash = _hash_leaf(entry)

        for direction, sibling_hex in proof:

            sibling = bytes.fromhex(sibling_hex)

            if direction == "right":
                current_hash = _hash_pair(current_hash, sibling)
            elif direction == "left":
                current_hash = _hash_pair(sibling, current_hash)
            else:
                raise ValueError("Invalid proof direction")

        return current_hash.hex() == expected_root_hex

    # ---------------------------------------------------------
    # Integrity Validation
    # ---------------------------------------------------------

    def validate_integrity(self) -> bool:

        if len(self._entries) != len(self._leaf_hashes):
            return False

        for entry, stored_hash in zip(self._entries, self._leaf_hashes):
            if _hash_leaf(entry) != stored_hash:
                return False

        # Recompute root deterministically
        if self._leaf_hashes:
            recomputed = _build_merkle_tree(self._leaf_hashes)[-1][0]
            if recomputed.hex() != self.merkle_root():
                return False

        return True

    # ---------------------------------------------------------
    # Seal
    # ---------------------------------------------------------

    def seal(self) -> None:
        self._sealed = True

    # ---------------------------------------------------------
    # Read-only
    # ---------------------------------------------------------

    def entries(self) -> List[Dict[str, Any]]:
        return [dict(e) for e in self._entries]

    def current_root(self) -> str | None:
        return self.merkle_root()

