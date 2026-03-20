import pytest

from app.security.track_d.anchoring.root_anchor_ledger import RootAnchorLedger
from app.security.track_d.anchoring.anchor_policy_engine import (
    AnchorPolicy,
    AnchorPolicyEngine,
)
from app.security.track_d.anchoring.anchor_receipt import AnchorReceipt


def _hash(i: int) -> str:
    return f"{i:064x}"


def _receipt(root_hash: str):
    return AnchorReceipt.create(
        root_hash=root_hash,
        network="mocknet",
        transaction_id=f"tx-{root_hash}",
        block_number=1,
        anchored_at="2026-01-01T00:00:00Z",
    )


def _ledger_with_n(n: int):
    policy = AnchorPolicy(
        version=1,
        required_networks=["mocknet"],
        minimum_total=1,
        allowed_networks=["mocknet"],
    )
    engine = AnchorPolicyEngine(policy)
    ledger = RootAnchorLedger(engine)

    for i in range(1, n + 1):
        ledger.append(
            certificate_hash=_hash(i),
            anchored_at=f"2026-01-{i:02d}T00:00:00Z",
            receipts=[_receipt(_hash(i))],
        )

    return ledger


def test_identical_chains():
    local = _ledger_with_n(3)
    remote = _ledger_with_n(3)

    assert local.snapshot() == remote.snapshot()


def test_remote_extends_local():
    local = _ledger_with_n(2)
    remote = _ledger_with_n(3)

    assert len(remote.snapshot()) > len(local.snapshot())


def test_truncation_detected():
    local = _ledger_with_n(3)
    remote = _ledger_with_n(2)

    assert len(remote.snapshot()) < len(local.snapshot())


def test_fork_detected():
    local = _ledger_with_n(3)
    remote = _ledger_with_n(3)

    fork = remote.snapshot()
    fork[2]["certificate_hash"] = _hash(999)
    remote._entries = fork

    with pytest.raises(ValueError):
        remote.validate_chain()
