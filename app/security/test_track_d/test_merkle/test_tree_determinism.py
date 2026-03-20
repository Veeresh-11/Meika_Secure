from app.security.track_d.merkle.tree import MerkleTree


def test_tree_deterministic():

    leaves1 = [b"a", b"b", b"c"]
    leaves2 = [b"c", b"a", b"b"]

    t1 = MerkleTree(leaves1)
    t2 = MerkleTree(leaves2)

    assert t1.get_root_hex() == t2.get_root_hex()
