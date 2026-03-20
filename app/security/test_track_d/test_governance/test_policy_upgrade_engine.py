import pytest

from app.security.track_d.anchoring.anchor_policy_engine import (
    AnchorPolicy,
    AnchorPolicyEngine,
)
from app.security.track_d.anchoring.anchor_policy_registry import (
    AnchorPolicyRegistry,
)
from app.security.track_d.anchoring.root_anchor_ledger import (
    RootAnchorLedger,
)
from app.security.track_d.anchoring.anchor_receipt import AnchorReceipt
from app.security.track_d.consensus.threshold_signature import (
    ThresholdSigner,
)
from app.security.track_d.governance.policy_upgrade_engine import (
    PolicyUpgradeEngine,
    PolicyUpgradeError,
)


def _receipt(root_hash: str):
    return AnchorReceipt.create(
        root_hash=root_hash,
        network="mocknet",
        transaction_id=f"tx-{root_hash}",
        block_number=1,
        anchored_at="2026-01-01T00:00:00Z",
    )


def _policy(version: int):
    return AnchorPolicy(
        version=version,
        required_networks=["mocknet"],
        minimum_total=1,
        allowed_networks=["mocknet"],
    )


def _environment():

    # Initial policy
    p1 = _policy(1)

    registry = AnchorPolicyRegistry()
    registry.register(p1)

    engine = AnchorPolicyEngine(p1)
    ledger = RootAnchorLedger(engine)

    return registry, ledger


def test_successful_policy_upgrade():

    registry, ledger = _environment()

    signer = ThresholdSigner.generate(total=3, threshold=2)

    new_policy = _policy(2)

    sig = signer.sign(new_policy.policy_hash)

    upgrade_engine = PolicyUpgradeEngine(
        registry=registry,
        ledger=ledger,
    )

    upgrade_engine.upgrade(
        new_policy=new_policy,
        previous_policy_hash=registry.latest().policy_hash,
        threshold_signature=sig,
        anchor_receipts=[_receipt(new_policy.policy_hash)],
        anchored_at="2026-01-02T00:00:00Z",
    )

    assert registry.latest().version == 2
    assert ledger.validate_chain() is True


def test_version_must_increment():

    registry, ledger = _environment()

    signer = ThresholdSigner.generate(total=3, threshold=2)

    bad_policy = _policy(1)  # same version

    sig = signer.sign(bad_policy.policy_hash)

    upgrade_engine = PolicyUpgradeEngine(
        registry=registry,
        ledger=ledger,
    )

    with pytest.raises(PolicyUpgradeError):
        upgrade_engine.upgrade(
            new_policy=bad_policy,
            previous_policy_hash=registry.latest().policy_hash,
            threshold_signature=sig,
            anchor_receipts=[_receipt(bad_policy.policy_hash)],
            anchored_at="2026-01-02T00:00:00Z",
        )


def test_previous_hash_mismatch():

    registry, ledger = _environment()

    signer = ThresholdSigner.generate(total=3, threshold=2)

    new_policy = _policy(2)

    sig = signer.sign(new_policy.policy_hash)

    upgrade_engine = PolicyUpgradeEngine(
        registry=registry,
        ledger=ledger,
    )

    with pytest.raises(PolicyUpgradeError):
        upgrade_engine.upgrade(
            new_policy=new_policy,
            previous_policy_hash="bad_hash",
            threshold_signature=sig,
            anchor_receipts=[_receipt(new_policy.policy_hash)],
            anchored_at="2026-01-02T00:00:00Z",
        )


def test_invalid_threshold_signature():

    registry, ledger = _environment()

    signer1 = ThresholdSigner.generate(total=3, threshold=2)
    signer2 = ThresholdSigner.generate(total=3, threshold=2)

    new_policy = _policy(2)

    # Sign with wrong signer
    sig = signer2.sign(new_policy.policy_hash)

    upgrade_engine = PolicyUpgradeEngine(
        registry=registry,
        ledger=ledger,
    )

    with pytest.raises(PolicyUpgradeError):
        upgrade_engine.upgrade(
            new_policy=new_policy,
            previous_policy_hash=registry.latest().policy_hash,
            threshold_signature=sig,
            anchor_receipts=[_receipt(new_policy.policy_hash)],
            anchored_at="2026-01-02T00:00:00Z",
        )
