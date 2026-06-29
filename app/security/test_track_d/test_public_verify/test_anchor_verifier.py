from app.security.track_d.public_verify.anchor_verifier import AnchorVerifier
from app.security.track_d.anchoring.mock_client import MockAnchorClient


def test_anchor_verification_success():

    client = MockAnchorClient()

    receipt = client.anchor("root-abc")

    verifier = AnchorVerifier(client)

    response = verifier.verify("root-abc").to_dict()

    assert response["verified"] is True
    assert response["object_type"] == "ANCHOR"
    assert response["proof"]["root_hash"] == "root-abc"


def test_anchor_verification_missing():

    client = MockAnchorClient()
    verifier = AnchorVerifier(client)

    response = verifier.verify("non-existent").to_dict()

    assert response["verified"] is False
    assert response["proof"] is None

from app.security.track_d.public_verify.anchor_verifier import AnchorVerifier


class NoReceiptClient:
    pass


def test_client_without_get_receipt():
    verifier = AnchorVerifier(NoReceiptClient())

    result = verifier.verify("a" * 64)

    assert result.verified is False
    assert result.object_type == "ANCHOR"