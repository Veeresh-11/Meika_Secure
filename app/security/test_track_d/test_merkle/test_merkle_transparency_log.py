import pytest

from app.security.track_d.transparency.merkle_transparency_log import (
    MerkleTransparencyLog,
)


GOOD_HASH = "a" * 64


def _append(log, payload=GOOD_HASH, result="PASS"):
    log.append(
        payload_hash=payload,
        policy_family="CORE",
        policy_version=1,
        result=result,
    )


# ---------------------------------------------------------
# Empty log
# ---------------------------------------------------------

def test_empty_log():
    log = MerkleTransparencyLog()

    assert log.entries() == []
    assert log.merkle_root() is None
    assert log.current_root() is None
    assert log.validate_integrity() is True


# ---------------------------------------------------------
# Append + root
# ---------------------------------------------------------

def test_append_generates_root():
    log = MerkleTransparencyLog()

    _append(log)

    assert len(log.entries()) == 1
    assert log.merkle_root() is not None
    assert log.current_root() == log.merkle_root()


# ---------------------------------------------------------
# Invalid result
# ---------------------------------------------------------

def test_invalid_result():
    log = MerkleTransparencyLog()

    with pytest.raises(ValueError, match="Invalid result value"):
        log.append(
            payload_hash=GOOD_HASH,
            policy_family=None,
            policy_version=None,
            result="INVALID",
        )


# ---------------------------------------------------------
# Invalid payload hash
# ---------------------------------------------------------

def test_invalid_payload_hash():
    log = MerkleTransparencyLog()

    with pytest.raises(ValueError, match="Invalid payload_hash"):
        log.append(
            payload_hash="abc",
            policy_family=None,
            policy_version=None,
            result="PASS",
        )


# ---------------------------------------------------------
# Seal
# ---------------------------------------------------------

def test_sealed_log_rejects_append():
    log = MerkleTransparencyLog()

    log.seal()

    with pytest.raises(ValueError, match="Transparency log is sealed"):
        _append(log)


# ---------------------------------------------------------
# Inclusion proof
# ---------------------------------------------------------

def test_inclusion_proof_round_trip():
    log = MerkleTransparencyLog()

    hashes = [
        "a" * 64,
        "b" * 64,
        "c" * 64,
        "d" * 64,
    ]

    for h in hashes:
        _append(log, payload=h)

    entries = log.entries()

    proof = log.get_inclusion_proof(2)

    assert MerkleTransparencyLog.verify_inclusion_proof(
        entries[2],
        proof,
        log.merkle_root(),
    )


# ---------------------------------------------------------
# Invalid proof index
# ---------------------------------------------------------

def test_invalid_proof_index_negative():
    log = MerkleTransparencyLog()

    _append(log)

    with pytest.raises(ValueError, match="Invalid index"):
        log.get_inclusion_proof(-1)


def test_invalid_proof_index_large():
    log = MerkleTransparencyLog()

    _append(log)

    with pytest.raises(ValueError, match="Invalid index"):
        log.get_inclusion_proof(5)


# ---------------------------------------------------------
# Invalid proof direction
# ---------------------------------------------------------

def test_invalid_proof_direction():
    log = MerkleTransparencyLog()

    _append(log)

    entry = log.entries()[0]

    with pytest.raises(ValueError, match="Invalid proof direction"):
        MerkleTransparencyLog.verify_inclusion_proof(
            entry,
            [("up", "0" * 64)],
            "0" * 64,
        )


# ---------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------

def test_validate_integrity_detects_entry_tampering():
    log = MerkleTransparencyLog()

    _append(log)

    log._entries[0]["result"] = "FAIL"

    assert log.validate_integrity() is False


def test_validate_integrity_detects_leaf_count_mismatch():
    log = MerkleTransparencyLog()

    _append(log)

    log._leaf_hashes.pop()

    assert log.validate_integrity() is False


# ---------------------------------------------------------
# Append blocked when integrity already broken
# ---------------------------------------------------------

def test_append_rejects_corrupted_log():
    log = MerkleTransparencyLog()

    _append(log)

    log._entries[0]["result"] = "FAIL"

    with pytest.raises(ValueError, match="Merkle log integrity violation"):
        _append(log)


# ---------------------------------------------------------
# entries() returns copy
# ---------------------------------------------------------

def test_entries_returns_copy():
    log = MerkleTransparencyLog()

    _append(log)

    returned = log.entries()

    returned[0]["result"] = "FAIL"

    assert log.entries()[0]["result"] == "PASS"


# ---------------------------------------------------------
# verify_inclusion_proof false case
# ---------------------------------------------------------

def test_verify_wrong_root_returns_false():
    log = MerkleTransparencyLog()

    _append(log)

    entry = log.entries()[0]

    proof = log.get_inclusion_proof(0)

    assert (
        MerkleTransparencyLog.verify_inclusion_proof(
            entry,
            proof,
            "0" * 64,
        )
        is False
    )
    
from app.security.track_d.transparency.merkle_transparency_log import (
    _build_merkle_tree,
)

def test_build_merkle_tree_empty():
    assert _build_merkle_tree([]) == []
    
def test_merkle_root_multiple_entries():
    log = MerkleTransparencyLog()

    for c in ("a", "b", "c"):
        log.append(
            payload_hash=c * 64,
            policy_family="CORE",
            policy_version=1,
            result="PASS",
        )

    root = log.merkle_root()

    assert isinstance(root, str)
    assert len(root) == 64
    
def test_single_leaf_inclusion_proof():
    log = MerkleTransparencyLog()

    log.append(
        payload_hash="a" * 64,
        policy_family="CORE",
        policy_version=1,
        result="PASS",
    )

    entry = log.entries()[0]

    proof = log.get_inclusion_proof(0)

    assert proof == []

    assert MerkleTransparencyLog.verify_inclusion_proof(
        entry,
        proof,
        log.merkle_root(),
    )
    
def test_inclusion_proof_odd_leaf_tree():
    log = MerkleTransparencyLog()

    for ch in ("a", "b", "c"):
        log.append(
            payload_hash=ch * 64,
            policy_family="CORE",
            policy_version=1,
            result="PASS",
        )

    proof = log.get_inclusion_proof(2)  # last leaf, duplicated sibling branch

    assert MerkleTransparencyLog.verify_inclusion_proof(
        log.entries()[2],
        proof,
        log.merkle_root(),
    )
    
def test_validate_integrity_detects_root_mismatch(monkeypatch):
    log = MerkleTransparencyLog()

    log.append(
        payload_hash="a" * 64,
        policy_family="CORE",
        policy_version=1,
        result="PASS",
    )

    monkeypatch.setattr(
        log,
        "merkle_root",
        lambda: "0" * 64,
    )

    assert log.validate_integrity() is False
    
