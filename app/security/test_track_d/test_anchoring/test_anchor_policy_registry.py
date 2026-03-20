import pytest

from app.security.track_d.anchoring.anchor_policy_registry import (
    AnchorPolicy,
    AnchorPolicyRegistry,
)


def _policy(v, total=1, nets=None):
    if nets is None:
        nets = ["mocknet"]
    return AnchorPolicy(
        version=v,
        minimum_total=total,
        allowed_networks=nets,
    )


def test_register_genesis_policy():

    registry = AnchorPolicyRegistry()

    p1 = _policy(1, total=1, nets=["mocknet"])

    registry.register(p1)

    latest = registry.latest()

    assert latest["version"] == 1
    assert registry.validate() is True


def test_version_must_increase():

    registry = AnchorPolicyRegistry()

    registry.register(_policy(1))

    with pytest.raises(ValueError):
        registry.register(_policy(1))


def test_minimum_total_downgrade_blocked():

    registry = AnchorPolicyRegistry()

    registry.register(_policy(1, total=2))

    with pytest.raises(ValueError):
        registry.register(_policy(2, total=1))


def test_network_downgrade_blocked():

    registry = AnchorPolicyRegistry()

    registry.register(_policy(1, nets=["mocknet", "ethereum"]))

    with pytest.raises(ValueError):
        registry.register(_policy(2, nets=["mocknet"]))


def test_upgrade_allowed():

    registry = AnchorPolicyRegistry()

    registry.register(_policy(1, total=1, nets=["mocknet"]))

    registry.register(_policy(2, total=2, nets=["mocknet", "ethereum"]))

    assert registry.latest()["version"] == 2
    assert registry.validate() is True


def test_tampering_detected():

    registry = AnchorPolicyRegistry()

    registry.register(_policy(1))

    snapshot = registry.snapshot()

    # Tamper minimum_total
    snapshot[0]["minimum_total"] = 999

    registry._policies = snapshot

    with pytest.raises(ValueError):
        registry.validate()


def test_get_by_version():

    registry = AnchorPolicyRegistry()

    registry.register(_policy(1))
    registry.register(_policy(2))

    p1 = registry.get(1)
    p2 = registry.get(2)

    assert p1["version"] == 1
    assert p2["version"] == 2


def test_empty_registry():

    registry = AnchorPolicyRegistry()

    assert registry.latest() is None
    assert registry.get(1) is None
    assert registry.validate() is True
