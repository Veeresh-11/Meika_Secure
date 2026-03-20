import pytest
from app.security.evidence.memory.replay import replay
from app.security.errors import SecurityInvariantViolation

def test_replay_accepts_valid_chain(evidence_chain):
    records = list(replay(evidence_chain))
    assert len(records) == len(evidence_chain)


def test_replay_detects_chain_break(evidence_chain):
    broken = list(evidence_chain)
    broken[2] = broken[2].__class__(
        sequence_number=broken[2].sequence_number,
        previous_hash="evil",
        payload_hash=broken[2].payload_hash,
        record_hash=broken[2].record_hash,
    )

    with pytest.raises(SecurityInvariantViolation):
        list(replay(broken))
