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
