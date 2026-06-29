import pytest

from app.security.track_d.anchoring.mock_client import MockAnchorClient
from app.security.track_d.anchoring.anchor_verifier import AnchorVerifier


def test_anchor_and_verify_success():

    client = MockAnchorClient()

    receipt = client.anchor("root-hash-123")

    verifier = AnchorVerifier(client)

    assert verifier.verify(receipt) is True


def test_anchor_transaction_not_found():

    client = MockAnchorClient()

    receipt = client.anchor("root-hash-123")

    # simulate network reset
    client = MockAnchorClient()

    verifier = AnchorVerifier(client)

    with pytest.raises(ValueError):
        verifier.verify(receipt)


def test_anchor_receipt_blockchain_mismatch():

    client = MockAnchorClient()

    receipt = client.anchor("root-hash-123")

    # simulate tampering by replacing ledger entry
    from app.security.track_d.anchoring.anchor_receipt import AnchorReceipt

    corrupted = AnchorReceipt(
        root_hash=receipt.root_hash,
        network=receipt.network,
        transaction_id=receipt.transaction_id,
        block_number=receipt.block_number,
        anchored_at=receipt.anchored_at,
        receipt_hash="tampered",
    )

    client._ledger[receipt.transaction_id] = corrupted

    verifier = AnchorVerifier(client)

    with pytest.raises(ValueError):
        verifier.verify(receipt)


def test_multiple_anchors_increment_block_number():

    client = MockAnchorClient()

    r1 = client.anchor("root1")
    r2 = client.anchor("root2")

    assert r2.block_number == r1.block_number + 1

def test_verify_receipt_wrapper():
    from app.security.track_d.anchoring.mock_client import MockAnchorClient

    client = MockAnchorClient()

    receipt = client.anchor("root123")

    assert client.verify_receipt(receipt) is True
    
import pytest

from app.security.track_d.anchoring.anchor_client import AnchorClient


def test_anchor_client_anchor_abstract():
    with pytest.raises(TypeError):
        AnchorClient()


def test_anchor_client_verify_abstract():
    with pytest.raises(TypeError):
        AnchorClient()