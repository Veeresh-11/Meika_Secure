import hashlib
import pytest   
from app.security.track_d.transparency.transparency_log import TransparencyLog
from app.security.track_d.public_verify.root_verifier import RootVerifier


def test_root_verification_success():

    log = TransparencyLog()

    root_hash = hashlib.sha256(b"root-123").hexdigest()

    log.append(
        payload_hash=root_hash,
        policy_family=None,
        policy_version=None,
        result="PASS",
    )

    verifier = RootVerifier(log)

    response = verifier.verify(root_hash).to_dict()

    assert response["verified"] is True
    assert response["object_type"] == "ROOT"
    assert response["proof"]["payload_hash"] == root_hash


def test_root_verification_not_found():

    log = TransparencyLog()
    verifier = RootVerifier(log)

    response = verifier.verify("unknown-root").to_dict()

    assert response["verified"] is False
    assert response["proof"] is None

def test_invalid_result_rejected():
    log = TransparencyLog()

    with pytest.raises(
        ValueError,
        match="Invalid result type",
    ):
        log.append(
            payload_hash="a" * 64,
            policy_family=None,
            policy_version=None,
            result="INVALID",
        )
        
def test_invalid_payload_hash():
    log = TransparencyLog()

    with pytest.raises(
        ValueError,
        match="Invalid payload_hash",
    ):
        log.append(
            payload_hash="abc",
            policy_family=None,
            policy_version=None,
            result="PASS",
        )
        
def test_chain_break_detected():
    log = TransparencyLog()

    log.append(
        payload_hash="a" * 64,
        policy_family=None,
        policy_version=None,
        result="PASS",
    )

    log.append(
        payload_hash="b" * 64,
        policy_family=None,
        policy_version=None,
        result="PASS",
    )

    # Break the linked list
    log._entries[1]["previous_hash"] = "broken"

    with pytest.raises(
        ValueError,
        match="Transparency chain broken",
    ):
        log.validate_chain()
        
def test_entries_returns_copy():
    log = TransparencyLog()

    log.append(
        payload_hash="a" * 64,
        policy_family=None,
        policy_version=None,
        result="PASS",
    )

    entries = log.entries()

    assert len(entries) == 1
    assert entries[0]["payload_hash"] == "a" * 64

    # Ensure it's a copy, not the internal list
    entries.clear()

    assert log.size() == 1