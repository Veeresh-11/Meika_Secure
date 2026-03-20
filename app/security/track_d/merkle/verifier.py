"""
Merkle Inclusion Proof Verifier
Fail-closed deterministic verification
"""

from __future__ import annotations

import hashlib
from typing import Dict, List


def _hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def verify_inclusion(
    *,
    leaf: bytes,
    proof_path: List[Dict],
    expected_root_hex: str,
) -> bool:

    current = _hash(leaf)

    for step in proof_path:

        sibling = bytes.fromhex(step["hash"])

        if step["direction"] == "left":
            current = hashlib.sha256(sibling + current).digest()
        elif step["direction"] == "right":
            current = hashlib.sha256(current + sibling).digest()
        else:
            raise ValueError("Invalid proof direction")

    return current.hex() == expected_root_hex
