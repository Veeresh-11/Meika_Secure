import pytest

from app.security.evidence.store import InMemoryEvidenceStore
from app.security.evidence.models import EvidenceRecord
from app.security.errors import SecurityInvariantViolation
from app.security.evidence.engine import GENESIS_HASH


def record(
    record_hash,
    previous_hash,
):
    return EvidenceRecord(
        sequence_number=1,
        previous_hash=previous_hash,
        payload_hash="payload",
        record_hash=record_hash,
    )


def test_chain_broken():

    store = InMemoryEvidenceStore()

    bad = record(
        "hash1",
        "wrong-prev",
    )

    with pytest.raises(
        SecurityInvariantViolation,
        match="EVIDENCE_CHAIN_BROKEN",
    ):
        store.append(bad)


def test_duplicate_hash():

    store = InMemoryEvidenceStore()

    first = record(
        "hash1",
        GENESIS_HASH,
    )

    store.append(first)

    duplicate = record(
        "hash1",
        "hash1",
    )

    with pytest.raises(
        SecurityInvariantViolation,
        match="EVIDENCE_DUPLICATE_HASH",
    ):
        store.append(duplicate)


def test_hashes_get_all():

    store = InMemoryEvidenceStore()

    first = record(
        "hash1",
        GENESIS_HASH,
    )

    store.append(first)

    hashes = store.hashes()

    assert hashes == ["hash1"]

    fetched = store.get("hash1")

    assert fetched.record_hash == "hash1"

    data = store.all()

    assert "hash1" in data

    data.clear()

    assert "hash1" in store.all()