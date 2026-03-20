import pytest
import hashlib
import json

from app.security.track_d.anchoring.anchor_receipt import AnchorReceipt


def _canonical(data: dict) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_receipt_deterministic_hash():

    receipt = AnchorReceipt.create(
        root_hash="abc123",
        network="ethereum-mainnet",
        transaction_id="0xdeadbeef",
        block_number=123,
        anchored_at="2026-01-01T00:00:00Z",
    )

    data = {
        "root_hash": "abc123",
        "network": "ethereum-mainnet",
        "transaction_id": "0xdeadbeef",
        "block_number": 123,
        "anchored_at": "2026-01-01T00:00:00Z",
    }

    expected = hashlib.sha256(_canonical(data)).hexdigest()

    assert receipt.receipt_hash == expected


def test_receipt_integrity_pass():

    receipt = AnchorReceipt.create(
        root_hash="abc123",
        network="ethereum-mainnet",
        transaction_id="0xdeadbeef",
        block_number=123,
        anchored_at="2026-01-01T00:00:00Z",
    )

    assert receipt.verify_integrity() is True


def test_receipt_tampering_detected():

    receipt = AnchorReceipt.create(
        root_hash="abc123",
        network="ethereum-mainnet",
        transaction_id="0xdeadbeef",
        block_number=123,
        anchored_at="2026-01-01T00:00:00Z",
    )

    # simulate tampering
    tampered = AnchorReceipt(
        root_hash="evil",
        network=receipt.network,
        transaction_id=receipt.transaction_id,
        block_number=receipt.block_number,
        anchored_at=receipt.anchored_at,
        receipt_hash=receipt.receipt_hash,
    )

    with pytest.raises(ValueError):
        tampered.verify_integrity()


def test_invalid_timestamp_rejected():

    with pytest.raises(ValueError):
        AnchorReceipt.create(
            root_hash="abc123",
            network="ethereum-mainnet",
            transaction_id="0xdeadbeef",
            block_number=123,
            anchored_at="invalid-timestamp",
        )
