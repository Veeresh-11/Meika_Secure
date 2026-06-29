# app/security/test_recovery_full.py

import hashlib
import pytest

from app.security.recovery import (
    export_evidence_store,
    restore_evidence_store,
    verify_store_integrity,
    compute_export_hash,
)

from app.security.evidence.models import EvidenceRecord
from app.security.errors import SecurityInvariantViolation
from app.security.evidence.engine import GENESIS_HASH


class FakeStore:

    def __init__(self, records=None):
        self.records = records or {}

    def last_hash(self):
        if not self.records:
            return None

        return list(self.records.keys())[-1]

    def get(self, record_hash):
        return self.records[record_hash]

    def append(self, record):
        self.records[record.record_hash] = record


def make_record(seq, previous_hash, payload_hash="payload"):

    record_hash = hashlib.sha256(
        f"{seq}|{previous_hash}|{payload_hash}".encode()
    ).hexdigest()

    return EvidenceRecord(
        sequence_number=seq,
        previous_hash=previous_hash,
        payload_hash=payload_hash,
        record_hash=record_hash,
    )


def test_export_empty_store():
    assert export_evidence_store(FakeStore()) == []


def test_verify_empty_store():
    assert verify_store_integrity(FakeStore()) is True


def test_restore_evidence_store():

    store = FakeStore()

    r0 = make_record(0, GENESIS_HASH)
    r1 = make_record(1, r0.record_hash)

    restore_evidence_store(store, [r0, r1])

    assert len(store.records) == 2


def test_verify_valid_chain():

    r0 = make_record(0, GENESIS_HASH)
    r1 = make_record(1, r0.record_hash)

    store = FakeStore({
        r0.record_hash: r0,
        r1.record_hash: r1,
    })

    assert verify_store_integrity(store) is True


def test_sequence_gap():

    r0 = make_record(0, GENESIS_HASH)

    r2 = make_record(
        2,
        r0.record_hash,
    )

    store = FakeStore({
        r0.record_hash: r0,
        r2.record_hash: r2,
    })

    with pytest.raises(SecurityInvariantViolation, match="SEQUENCE_GAP"):
        verify_store_integrity(store)

def test_chain_link_broken():

    r0 = make_record(0, GENESIS_HASH)

    fake_prev_hash = hashlib.sha256(
        f"0|{GENESIS_HASH}|fake".encode()
    ).hexdigest()

    fake_prev = EvidenceRecord(
        sequence_number=0,
        previous_hash=GENESIS_HASH,
        payload_hash="fake",
        record_hash=fake_prev_hash,
    )

    r1 = make_record(
        1,
        fake_prev_hash,
    )

    records = [r0, r1]

    # monkeypatch export directly
    from app.security import recovery

    original = recovery.export_evidence_store

    recovery.export_evidence_store = lambda store: records

    try:
        with pytest.raises(
            SecurityInvariantViolation,
            match="CHAIN_LINK_BROKEN",
        ):
            verify_store_integrity(object())
    finally:
        recovery.export_evidence_store = original

def test_chain_hash_mismatch():

    r0 = make_record(0, GENESIS_HASH)

    r1 = EvidenceRecord(
        sequence_number=1,
        previous_hash=r0.record_hash,
        payload_hash="payload",
        record_hash="tampered",
    )

    store = FakeStore({
        r0.record_hash: r0,
        r1.record_hash: r1,
    })

    with pytest.raises(SecurityInvariantViolation, match="CHAIN_HASH_MISMATCH"):
        verify_store_integrity(store)


def test_compute_export_hash():

    r0 = make_record(0, GENESIS_HASH)

    digest = compute_export_hash([r0])

    assert isinstance(digest, str)
    assert len(digest) == 64