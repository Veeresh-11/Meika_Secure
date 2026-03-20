from app.security.track_d.merkle.tree import MerkleTree
from app.security.track_d.merkle.proof import generate_proof
from app.security.track_d.merkle.verifier import verify_inclusion


def test_tampered_proof_fails():

    leaves = [b"a", b"b", b"c"]
    tree = MerkleTree(leaves)

    proof = generate_proof(tree, b"b")

    # Tamper sibling hash
    proof.proof_path[0]["hash"] = "00" * 32

    assert not verify_inclusion(
        leaf=b"b",
        proof_path=proof.proof_path,
        expected_root_hex=tree.get_root_hex(),
    )
