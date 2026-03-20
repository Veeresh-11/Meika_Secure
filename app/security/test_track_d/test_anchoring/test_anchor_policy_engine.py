import pytest

from app.security.track_d.anchoring.anchor_policy import AnchorPolicy
from app.security.track_d.anchoring.anchor_policy_engine import AnchorPolicyEngine
from app.security.track_d.anchoring.anchor_receipt import AnchorReceipt


def _receipt(network: str) -> AnchorReceipt:
    return AnchorReceipt.create(
        root_hash="abc",
        network=network,
        transaction_id=f"tx-{network}",
        block_number=1,
        anchored_at="2026-01-01T00:00:00Z",
    )


def test_policy_structure_validation():
    policy = AnchorPolicy(
        version=1,
        required_networks=["ethereum"],
        minimum_total=1,
        allowed_networks=["ethereum", "polygon"],
    )
    policy.validate_structure()


def test_policy_invalid_required_subset():
    policy = AnchorPolicy(
        version=1,
        required_networks=["bitcoin"],
        minimum_total=1,
        allowed_networks=["ethereum"],
    )

    with pytest.raises(ValueError):
        policy.validate_structure()


def test_policy_engine_success():
    policy = AnchorPolicy(
        version=1,
        required_networks=["ethereum"],
        minimum_total=2,
        allowed_networks=["ethereum", "polygon"],
    )

    engine = AnchorPolicyEngine(policy)

    receipts = [
        _receipt("ethereum"),
        _receipt("polygon"),
    ]

    assert engine.evaluate(receipts) is True


def test_policy_missing_required_network():
    policy = AnchorPolicy(
        version=1,
        required_networks=["ethereum"],
        minimum_total=1,
        allowed_networks=["ethereum", "polygon"],
    )

    engine = AnchorPolicyEngine(policy)

    receipts = [_receipt("polygon")]

    assert engine.evaluate(receipts) is False


def test_policy_insufficient_total():
    policy = AnchorPolicy(
        version=1,
        required_networks=["ethereum"],
        minimum_total=2,
        allowed_networks=["ethereum", "polygon"],
    )

    engine = AnchorPolicyEngine(policy)

    receipts = [_receipt("ethereum")]

    assert engine.evaluate(receipts) is False


def test_policy_unapproved_network():
    policy = AnchorPolicy(
        version=1,
        required_networks=["ethereum"],
        minimum_total=1,
        allowed_networks=["ethereum"],
    )

    engine = AnchorPolicyEngine(policy)

    receipts = [
        _receipt("ethereum"),
        _receipt("polygon"),
    ]

    assert engine.evaluate(receipts) is False
