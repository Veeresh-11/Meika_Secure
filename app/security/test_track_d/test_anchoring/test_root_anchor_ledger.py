import pytest

from app.security.track_d.anchoring.root_anchor_ledger import RootAnchorLedger
from app.security.track_d.anchoring.anchor_receipt import AnchorReceipt
from app.security.track_d.anchoring.anchor_policy_engine import (
    AnchorPolicy,
    AnchorPolicyEngine,
)


def _hash(i: int) -> str:
    return f"{i:064x}"


def _receipt(root_hash: str, network: str = "mocknet") -> AnchorReceipt:
    return AnchorReceipt.create(
        root_hash=root_hash,
        network=network,
        transaction_id=f"tx-{root_hash}-{network}",
        block_number=1,
        anchored_at="2026-01-01T00:00:00Z",
    )


def _policy():
    return AnchorPolicy(
        version=1,
        required_networks=["mocknet"],
        minimum_total=1,
        allowed_networks=["mocknet"],
    )


def _ledger():
    engine = AnchorPolicyEngine(_policy())
    return RootAnchorLedger(engine)


# ---------------------------------------------------------
# Genesis
# ---------------------------------------------------------

def test_genesis_append():

    ledger = _ledger()
    receipt = _receipt(_hash(1))

    ledger.append(
        certificate_hash=_hash(1),
        anchored_at="2026-01-01T00:00:00Z",
        receipts=[receipt],
    )

    latest = ledger.latest()

    assert latest["previous_entry_hash"] is None
    assert latest["policy_version"] == 1
    assert "policy_hash" in latest
    assert ledger.validate_chain() is True


# ---------------------------------------------------------
# Sequential Append
# ---------------------------------------------------------

def test_sequential_append():

    ledger = _ledger()

    r1 = _receipt(_hash(1))
    r2 = _receipt(_hash(2))

    ledger.append(
        certificate_hash=_hash(1),
        anchored_at="2026-01-01T00:00:00Z",
        receipts=[r1],
    )

    ledger.append(
        certificate_hash=_hash(2),
        anchored_at="2026-01-02T00:00:00Z",
        receipts=[r2],
    )

    assert ledger.validate_chain() is True


# ---------------------------------------------------------
# Timestamp Monotonicity
# ---------------------------------------------------------

def test_timestamp_monotonicity_enforced():

    ledger = _ledger()

    r1 = _receipt(_hash(1))
    r2 = _receipt(_hash(2))

    ledger.append(
        certificate_hash=_hash(1),
        anchored_at="2026-01-02T00:00:00Z",
        receipts=[r1],
    )

    with pytest.raises(ValueError):
        ledger.append(
            certificate_hash=_hash(2),
            anchored_at="2026-01-01T00:00:00Z",
            receipts=[r2],
        )


# ---------------------------------------------------------
# Tampering Detection
# ---------------------------------------------------------

def test_tampering_detected():

    ledger = _ledger()

    r1 = _receipt(_hash(1))
    r2 = _receipt(_hash(2))

    ledger.append(
        certificate_hash=_hash(1),
        anchored_at="2026-01-01T00:00:00Z",
        receipts=[r1],
    )

    ledger.append(
        certificate_hash=_hash(2),
        anchored_at="2026-01-02T00:00:00Z",
        receipts=[r2],
    )

    snapshot = ledger.snapshot()
    snapshot[1]["certificate_hash"] = _hash(999)
    ledger._entries = snapshot

    with pytest.raises(ValueError):
        ledger.validate_chain()


# ---------------------------------------------------------
# Fork Detection
# ---------------------------------------------------------

def test_fork_detection():

    ledger = _ledger()

    r1 = _receipt(_hash(1))
    r2 = _receipt(_hash(2))

    ledger.append(
        certificate_hash=_hash(1),
        anchored_at="2026-01-01T00:00:00Z",
        receipts=[r1],
    )

    ledger.append(
        certificate_hash=_hash(2),
        anchored_at="2026-01-02T00:00:00Z",
        receipts=[r2],
    )

    snapshot = ledger.snapshot()
    snapshot[1]["previous_entry_hash"] = None
    ledger._entries = snapshot

    with pytest.raises(ValueError):
        ledger.validate_chain()


# ---------------------------------------------------------
# Policy Violation (append-time enforcement)
# ---------------------------------------------------------

def test_policy_violation_detected():

    policy = AnchorPolicy(
        version=1,
        required_networks=["ethereum"],
        minimum_total=1,
        allowed_networks=["ethereum"],
    )

    engine = AnchorPolicyEngine(policy)
    ledger = RootAnchorLedger(engine)

    receipt = _receipt(_hash(1), network="mocknet")

    with pytest.raises(ValueError):
        ledger.append(
            certificate_hash=_hash(1),
            anchored_at="2026-01-01T00:00:00Z",
            receipts=[receipt],
        )


# ---------------------------------------------------------
# Governance Tampering Detection
# ---------------------------------------------------------

def test_policy_hash_mismatch_detected():

    ledger = _ledger()

    receipt = _receipt(_hash(1))

    ledger.append(
        certificate_hash=_hash(1),
        anchored_at="2026-01-01T00:00:00Z",
        receipts=[receipt],
    )

    # Mutate policy engine after append
    new_policy = AnchorPolicy(
        version=2,
        required_networks=["mocknet"],
        minimum_total=1,
        allowed_networks=["mocknet"],
    )

    ledger._policy_engine = AnchorPolicyEngine(new_policy)

    with pytest.raises(ValueError):
        ledger.validate_chain()
