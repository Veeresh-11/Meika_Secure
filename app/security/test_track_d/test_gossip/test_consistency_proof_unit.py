# app/security/test_track_d/test_gossip/test_consistency_proof_unit.py

from app.security.track_d.gossip.consistency_proof import (
    ConsistencyProof,
)


def test_empty_proof():
    proof = ConsistencyProof([])

    assert proof.first_hash() is None
    assert proof.last_hash() is None
    assert proof.length() == 0


def test_single_entry():
    proof = ConsistencyProof(
        [
            {"entry_hash": "abc"}
        ]
    )

    assert proof.first_hash() == "abc"
    assert proof.last_hash() == "abc"
    assert proof.length() == 1


def test_multiple_entries():
    proof = ConsistencyProof(
        [
            {"entry_hash": "a"},
            {"entry_hash": "b"},
            {"entry_hash": "c"},
        ]
    )

    assert proof.first_hash() == "a"
    assert proof.last_hash() == "c"
    assert proof.length() == 3