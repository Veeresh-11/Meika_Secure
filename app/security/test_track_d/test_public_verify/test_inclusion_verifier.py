from app.security.track_d.public_verify.inclusion_verifier import InclusionVerifier
from app.security.track_d.transparency.merkle_transparency_log import (
    MerkleTransparencyLog,
)


def test_inclusion_success():

    log = MerkleTransparencyLog()

    leaf = "leaf-1"
    log.append(
    payload_hash="leaf-1".ljust(64, "0"),
    policy_family=None,
    policy_version=None,
    result="PASS",
    )

    root_hash = log.current_root()

    verifier = InclusionVerifier(log)

    response = verifier.verify(root_hash, leaf).to_dict()

    assert response["verified"] is True
    assert response["object_type"] == "INCLUSION"
    assert response["proof"] is not None


def test_inclusion_invalid_leaf():

    log = MerkleTransparencyLog()

    log.append(
    payload_hash="leaf-1".ljust(64, "0"),
    policy_family=None,
    policy_version=None,
    result="PASS",
    )

    root_hash = log.current_root()

    verifier = InclusionVerifier(log)

    response = verifier.verify(root_hash, "unknown-leaf").to_dict()

    assert response["verified"] is False
    assert response["proof"] is None
