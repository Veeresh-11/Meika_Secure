"""
Merkle Inclusion Proof Generator
"""

from __future__ import annotations

from typing import List, Dict, Any

from .tree import MerkleTree


class InclusionProof:

    def __init__(self, leaf: bytes, proof_path: List[Dict[str, Any]]):
        self.leaf = leaf
        self.proof_path = proof_path  # [{"direction": "left"|"right", "hash": hex}]


def generate_proof(tree: MerkleTree, leaf: bytes) -> InclusionProof:

    if not tree.root:
        raise ValueError("Cannot generate proof for empty tree")

    leaf_hash = tree.levels[0][tree.leaves.index(leaf)]

    index = tree.leaves.index(leaf)

    proof_path = []

    for level in tree.levels[:-1]:

        is_right_node = index % 2
        sibling_index = index - 1 if is_right_node else index + 1

        if sibling_index >= len(level):
            sibling_hash = level[index]  # duplicate case
        else:
            sibling_hash = level[sibling_index]

        direction = "left" if is_right_node else "right"

        proof_path.append({
            "direction": direction,
            "hash": sibling_hash.hex(),
        })

        index //= 2

    return InclusionProof(leaf, proof_path)
