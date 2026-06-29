from app.security.track_d.merkle.tree import MerkleTree
from app.security.track_d.merkle.proof import generate_proof
from app.security.track_d.merkle.verifier import verify_inclusion


def test_valid_inclusion_proof():

    leaves = [b"a", b"b", b"c", b"d"]
    tree = MerkleTree(leaves)

    proof = generate_proof(tree, b"c")

    assert verify_inclusion(
        leaf=b"c",
        proof_path=proof.proof_path,
        expected_root_hex=tree.get_root_hex(),
    )

import pytest

from app.security.track_d.merkle.verifier import verify_inclusion


def test_invalid_proof_direction():
    with pytest.raises(ValueError, match="Invalid proof direction"):
        verify_inclusion(
            leaf=b"test",
            proof_path=[
                {
                    "hash": "00" * 32,
                    "direction": "up",   # invalid
                }
            ],
            expected_root_hex="00" * 32,
        )
def test_empty_tree():
    tree = MerkleTree([])

    assert tree.root is None
    assert tree.levels == []
    assert tree.get_root_hex() is None
    
def test_empty_tree_proof():
    tree = MerkleTree([])

    with pytest.raises(ValueError, match="Cannot generate proof"):
        generate_proof(tree, b"x")
        
def test_duplicate_last_leaf_branch():
    tree = MerkleTree([
        b"a",
        b"b",
        b"c",
    ])

    proof = generate_proof(tree, b"c")

    assert len(proof.proof_path) > 0