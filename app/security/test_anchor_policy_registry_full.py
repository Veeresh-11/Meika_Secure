import pytest

from app.security.track_d.anchoring.anchor_policy_engine import AnchorPolicy
from app.security.track_d.anchoring.anchor_policy_registry import (
    AnchorPolicyRegistry,
    _canonical,
    _hash,
)


def policy(
    version,
    minimum_total=1,
    allowed=None,
    required=None,
):
    return AnchorPolicy(
        version=version,
        minimum_total=minimum_total,
        allowed_networks=allowed or ["eth"],
        required_networks=required or ["eth"],
    )


# --------------------------------------------------
# helper functions
# --------------------------------------------------

def test_canonical():
    data = {"b": 2, "a": 1}

    result = _canonical(data)

    assert isinstance(result, bytes)
    assert result == b'{"a":1,"b":2}'


def test_hash():
    data = {"a": 1}

    h1 = _hash(data)
    h2 = _hash(data)

    assert h1 == h2
    assert len(h1) == 64


# --------------------------------------------------
# latest / latest_hash empty
# --------------------------------------------------

def test_empty_registry():
    reg = AnchorPolicyRegistry()

    assert reg.latest() is None
    assert reg.latest_hash() is None
    assert reg.get(1) is None
    assert reg.snapshot() == []
    assert reg.validate() is True


# --------------------------------------------------
# register success
# --------------------------------------------------

def test_register_first_policy():
    reg = AnchorPolicyRegistry()

    p = policy(1)

    reg.register(p)

    latest = reg.latest()

    assert latest.version == 1
    assert reg.latest_hash() == p.policy_hash


# --------------------------------------------------
# validation failures
# --------------------------------------------------

def test_version_must_be_positive():
    reg = AnchorPolicyRegistry()

    with pytest.raises(ValueError):
        reg.register(policy(0))


def test_minimum_total_must_be_positive():
    reg = AnchorPolicyRegistry()

    with pytest.raises(ValueError):
        reg.register(
            AnchorPolicy(
                version=1,
                minimum_total=0,
                allowed_networks=["eth"],
                required_networks=["eth"],
            )
        )


def test_allowed_networks_required():
    reg = AnchorPolicyRegistry()

    with pytest.raises(ValueError):
        reg.register(
            AnchorPolicy(
                version=1,
                minimum_total=1,
                allowed_networks=[],
                required_networks=[],
            )
        )


# --------------------------------------------------
# downgrade protection
# --------------------------------------------------

def test_version_must_increase():
    reg = AnchorPolicyRegistry()

    reg.register(policy(1))

    with pytest.raises(ValueError):
        reg.register(policy(1))


def test_minimum_total_downgrade():
    reg = AnchorPolicyRegistry()

    reg.register(policy(1, minimum_total=3))

    with pytest.raises(ValueError):
        reg.register(policy(2, minimum_total=2))


def test_allowed_network_downgrade():
    reg = AnchorPolicyRegistry()

    reg.register(
        policy(
            1,
            allowed=["eth", "btc"],
            required=["eth"],
        )
    )

    with pytest.raises(ValueError):
        reg.register(
            policy(
                2,
                allowed=["eth"],
                required=["eth"],
            )
        )


# --------------------------------------------------
# get / snapshot
# --------------------------------------------------

def test_get_policy():
    reg = AnchorPolicyRegistry()

    p = policy(1)

    reg.register(p)

    result = reg.get(1)

    assert result["version"] == 1
    assert result["policy_hash"] == p.policy_hash


def test_snapshot():
    reg = AnchorPolicyRegistry()

    reg.register(policy(1))
    reg.register(
        policy(
            2,
            allowed=["eth", "btc"],
            required=["eth"],
        )
    )

    snap = reg.snapshot()

    assert len(snap) == 2


# --------------------------------------------------
# validate success
# --------------------------------------------------

def test_validate_success():
    reg = AnchorPolicyRegistry()

    reg.register(policy(1))

    reg.register(
        policy(
            2,
            allowed=["eth", "btc"],
            required=["eth"],
        )
    )

    assert reg.validate() is True


# --------------------------------------------------
# validate version ordering
# --------------------------------------------------

def test_validate_version_ordering_violation():
    reg = AnchorPolicyRegistry()

    reg._policies = [
        {
            "version": 2,
            "minimum_total": 1,
            "allowed_networks": ["eth"],
            "required_networks": ["eth"],
            "policy_hash": policy(2).policy_hash,
        },
        {
            "version": 1,
            "minimum_total": 1,
            "allowed_networks": ["eth"],
            "required_networks": ["eth"],
            "policy_hash": policy(1).policy_hash,
        },
    ]

    with pytest.raises(ValueError, match="ordering"):
        reg.validate()


# --------------------------------------------------
# validate tampering
# --------------------------------------------------

def test_validate_tampering():
    reg = AnchorPolicyRegistry()

    p = policy(1)

    reg.register(p)

    reg._policies[0]["policy_hash"] = "tampered"

    with pytest.raises(ValueError, match="tampering"):
        reg.validate()
        
def test_get_second_policy():
    reg = AnchorPolicyRegistry()

    reg.register(policy(1))

    reg.register(
        policy(
            2,
            allowed=["eth", "btc"],
            required=["eth"],
        )
    )

    result = reg.get(2)

    assert result is not None
    assert result["version"] == 2