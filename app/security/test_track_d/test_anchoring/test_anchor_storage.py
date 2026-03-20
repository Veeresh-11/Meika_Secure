import pytest
from app.security.track_d.anchoring.anchor_storage import AnchorStorage
from app.security.track_d.anchoring.anchor_receipt import AnchorReceipt


def make_receipt(i: int) -> AnchorReceipt:
    return AnchorReceipt.create(
        root_hash=f"root-{i}",
        network="mocknet",
        transaction_id=f"tx-{i}",
        block_number=i,
        anchored_at="2026-01-01T00:00:00Z",
    )


def test_store_and_lookup_transaction():
    storage = AnchorStorage()

    receipt = make_receipt(1)
    storage.store(receipt)

    loaded = storage.get_by_transaction("tx-1")

    assert loaded is not None
    assert loaded.root_hash == "root-1"


def test_store_and_lookup_root():
    storage = AnchorStorage()

    receipt = make_receipt(2)
    storage.store(receipt)

    loaded = storage.get_by_root("root-2")

    assert loaded is not None
    assert loaded.transaction_id == "tx-2"


def test_duplicate_insert_rejected():
    storage = AnchorStorage()

    receipt = make_receipt(3)
    storage.store(receipt)

    with pytest.raises(ValueError):
        storage.store(receipt)


def test_list_ordered():
    storage = AnchorStorage()

    for i in range(1, 4):
        storage.store(make_receipt(i))

    receipts = storage.list_all()

    assert receipts[0].block_number == 1
    assert receipts[1].block_number == 2
    assert receipts[2].block_number == 3


def test_size():
    storage = AnchorStorage()

    for i in range(1, 6):
        storage.store(make_receipt(i))

    assert storage.size() == 5


def test_integrity_violation_detection():
    storage = AnchorStorage()

    receipt = make_receipt(10)
    storage.store(receipt)

    # Direct DB tampering
    cursor = storage.conn.cursor()
    cursor.execute(
        "UPDATE anchor_receipts SET receipt_hash='tampered' WHERE transaction_id='tx-10'"
    )
    storage.conn.commit()

    with pytest.raises(ValueError):
        storage.get_by_transaction("tx-10")
