import hashlib

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
