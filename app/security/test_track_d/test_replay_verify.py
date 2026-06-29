import hashlib
import pytest

from app.security.evidence.models import EvidenceRecord
from app.security.evidence.engine import GENESIS_HASH

from app.security.track_d.replay_verify import (
    verify_evidence_chain,
    verify_or_raise,
)

from app.security.errors import SecurityInvariantViolation


def make_record(seq, previous_hash, payload="payload"):
    record_hash = hashlib.sha256(
        f"{seq}|{previous_hash}|{payload}".encode()
    ).hexdigest()

    return EvidenceRecord(
        sequence_number=seq,
        previous_hash=previous_hash,
        payload_hash=payload,
        record_hash=record_hash,
    )


def test_empty_chain():
    result = verify_evidence_chain([])

    assert result.valid is False
    assert result.failure_code == "MEIKA_REPLAY_EMPTY_CHAIN"


def test_valid_chain():
    r0 = make_record(0, GENESIS_HASH)

    r1 = make_record(
        1,
        r0.record_hash,
    )

    result = verify_evidence_chain([r0, r1])

    assert result.valid is True


def test_sequence_gap():
    r0 = make_record(0, GENESIS_HASH)

    r2 = make_record(
        2,
        r0.record_hash,
    )

    result = verify_evidence_chain([r0, r2])

    assert result.valid is False
    assert result.failure_code == "MEIKA_REPLAY_SEQUENCE_GAP"


def test_previous_hash_mismatch():
    r0 = make_record(0, GENESIS_HASH)

    r1 = make_record(
        1,
        "bad_previous_hash",
    )

    result = verify_evidence_chain([r0, r1])

    assert result.valid is False
    assert result.failure_code == "MEIKA_REPLAY_PREVIOUS_HASH_MISMATCH"


def test_hash_mismatch():
    r0 = make_record(0, GENESIS_HASH)

    r1 = EvidenceRecord(
        sequence_number=1,
        previous_hash=r0.record_hash,
        payload_hash="payload",
        record_hash="tampered",
    )

    result = verify_evidence_chain([r0, r1])

    assert result.valid is False
    assert result.failure_code == "MEIKA_REPLAY_HASH_MISMATCH"


def test_input_not_iterable():
    result = verify_evidence_chain(None)

    assert result.valid is False
    assert result.failure_code == "MEIKA_REPLAY_INPUT_INVALID"


def test_verify_or_raise_success():
    r0 = make_record(0, GENESIS_HASH)

    verify_or_raise([r0])


def test_verify_or_raise_failure():
    with pytest.raises(SecurityInvariantViolation):
        verify_or_raise([])
        
from app.security.track_d.replay_verify import verify_evidence_chain


class BrokenRecord:
    sequence_number = 1
    previous_hash = "0" * 64
    record_hash = "x"

    @property
    def payload_hash(self):
        raise RuntimeError("boom")


def test_hash_compute_failed():
    result = verify_evidence_chain([BrokenRecord()])

    assert result.valid is False
    assert result.failure_code == "MEIKA_REPLAY_HASH_COMPUTE_FAILED"
    assert result.failure_stage == "HASH"