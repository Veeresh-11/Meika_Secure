import pytest

from app.security.track_d.gossip.gossip_verifier import (
    GossipVerifier,
)


class FakeLedger:
    def __init__(self, entries):
        self.entries = entries

    def validate_chain(self):
        return None

    def snapshot(self):
        return self.entries


def test_identical_chain():
    entries = [{"id": 1}, {"id": 2}]

    verifier = GossipVerifier(
        FakeLedger(entries)
    )

    assert verifier.verify_remote_chain(entries)


def test_remote_extends_local():
    local = [{"id": 1}]
    remote = [{"id": 1}, {"id": 2}]

    verifier = GossipVerifier(
        FakeLedger(local)
    )

    assert verifier.verify_remote_chain(remote)


def test_fork_detected():
    local = [{"id": 1}]
    remote = [{"id": 999}]

    verifier = GossipVerifier(
        FakeLedger(local)
    )

    with pytest.raises(ValueError):
        verifier.verify_remote_chain(remote)


def test_remote_truncated():
    local = [
        {"id": 1},
        {"id": 2},
    ]

    remote = [
        {"id": 1},
    ]

    verifier = GossipVerifier(
        FakeLedger(local)
    )

    with pytest.raises(ValueError):
        verifier.verify_remote_chain(remote)
        
def test_remote_shorter_with_divergence():

    local = [
        {"id": 1},
        {"id": 2},
    ]

    remote = [
        {"id": 999},
    ]

    verifier = GossipVerifier(
        FakeLedger(local)
    )

    with pytest.raises(
        ValueError,
        match="Fork detected: divergence",
    ):
        verifier.verify_remote_chain(remote)