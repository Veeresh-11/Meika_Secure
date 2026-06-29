import hashlib
import pytest

from app.security.evidence.models import EvidenceRecord
from app.security.evidence.verify import verify_chain
from app.security.evidence.engine import GENESIS_HASH
from app.security.errors import SecurityInvariantViolation


def make_record(seq, prev, payload):

    record_hash = hashlib.sha256(
        f"{seq}|{prev}|{payload}".encode()
    ).hexdigest()

    return EvidenceRecord(
        sequence_number=seq,
        previous_hash=prev,
        payload_hash=payload,
        record_hash=record_hash,
    )


def test_verify_chain_success():

    r1 = make_record(
        0,
        GENESIS_HASH,
        "payload1",
    )

    r2 = make_record(
        1,
        r1.record_hash,
        "payload2",
    )

    assert verify_chain([r1, r2]) is True


def test_verify_chain_sequence_gap():

    r1 = make_record(
        1,  # should start at 0
        GENESIS_HASH,
        "payload1",
    )

    with pytest.raises(
        SecurityInvariantViolation,
        match="SEQUENCE_GAP",
    ):
        verify_chain([r1])


def test_verify_chain_link_broken():

    r1 = make_record(
        0,
        "wrong-prev",
        "payload1",
    )

    with pytest.raises(
        SecurityInvariantViolation,
        match="CHAIN_LINK_BROKEN",
    ):
        verify_chain([r1])


def test_verify_chain_hash_mismatch():

    r1 = EvidenceRecord(
        sequence_number=0,
        previous_hash=GENESIS_HASH,
        payload_hash="payload1",
        record_hash="tampered",
    )

    with pytest.raises(
        SecurityInvariantViolation,
        match="CHAIN_HASH_MISMATCH",
    ):
        verify_chain([r1])