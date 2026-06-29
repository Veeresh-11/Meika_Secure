from types import SimpleNamespace

from app.security.evidence.engine import (
    build_anchor_record,
    append_evidence_record,
    build_governance_upgrade_record,
    EvidenceCommitReceipt,
    GENESIS_HASH,
)

from app.security.evidence.store import (
    InMemoryEvidenceStore,
)


def test_build_anchor_record():

    store = InMemoryEvidenceStore()

    record = build_anchor_record(
        root_hash="root123",
        record_count=7,
        anchor_receipt={"tx": "abc"},
        store=store,
    )

    assert record.sequence_number == 0
    assert record.previous_hash == GENESIS_HASH
    assert record.payload_hash
    assert record.record_hash


def test_append_evidence_record_success():

    store = InMemoryEvidenceStore()

    record = build_anchor_record(
        root_hash="root123",
        record_count=1,
        anchor_receipt={"tx": "abc"},
        store=store,
    )

    receipt = append_evidence_record(
        record,
        store=store,
    )

    assert isinstance(
        receipt,
        EvidenceCommitReceipt,
    )

    assert receipt.merkle_root == record.record_hash


def test_append_evidence_record_failure():

    class BrokenStore:

        def append(self, record):
            raise RuntimeError("boom")

    record = SimpleNamespace()

    receipt = append_evidence_record(
        record,
        store=BrokenStore(),
    )

    assert receipt is None


def test_build_governance_upgrade_record():

    store = InMemoryEvidenceStore()

    manifest = SimpleNamespace(
        migration_id="mig-1",
        from_version="1",
        to_version="2",
        migration_hash="hash123",
        signed_by="governance",
    )

    record = build_governance_upgrade_record(
        manifest=manifest,
        store=store,
    )

    assert record.sequence_number == 0
    assert record.previous_hash == GENESIS_HASH
    assert record.payload_hash
    assert record.record_hash