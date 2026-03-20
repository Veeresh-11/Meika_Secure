import pytest

from app.security.track_d.governance.governance_registry import (
    GovernanceRegistry,
)


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def _setup_registry():
    registry = GovernanceRegistry()

    registry.add_policy(
        policy_family="ROOT_POLICY",
        version=1,
        effective_from="2026-01-01T00:00:00Z",
        minimum_weight=3,
        required_roles=["SECURITY_OFFICER"],
    )

    return registry


# ---------------------------------------------------------
# Monotonic Version Enforcement
# ---------------------------------------------------------

def test_version_must_increase():
    registry = _setup_registry()

    with pytest.raises(Exception):
        registry.add_policy(
            policy_family="ROOT_POLICY",
            version=1,  # same version
            effective_from="2026-02-01T00:00:00Z",
            minimum_weight=5,
        )


# ---------------------------------------------------------
# Backdating Protection
# ---------------------------------------------------------

def test_backdating_rejected():
    registry = _setup_registry()

    with pytest.raises(Exception):
        registry.add_policy(
            policy_family="ROOT_POLICY",
            version=2,
            effective_from="2025-12-01T00:00:00Z",  # earlier than v1
            minimum_weight=5,
        )


# ---------------------------------------------------------
# Governance Chain Integrity
# ---------------------------------------------------------

def test_chain_validation():
    registry = _setup_registry()

    registry.add_policy(
        policy_family="ROOT_POLICY",
        version=2,
        effective_from="2026-02-01T00:00:00Z",
        minimum_weight=5,
    )

    assert registry.validate_chain("ROOT_POLICY")


# ---------------------------------------------------------
# Tampering Detection
# ---------------------------------------------------------

def test_tampering_detected():
    registry = _setup_registry()

    registry.add_policy(
        policy_family="ROOT_POLICY",
        version=2,
        effective_from="2026-02-01T00:00:00Z",
        minimum_weight=5,
    )

    # Tamper with stored entry
    registry._families["ROOT_POLICY"][0]["minimum_weight"] = 999

    with pytest.raises(Exception):
        registry.validate_chain("ROOT_POLICY")


# ---------------------------------------------------------
# Constitutional Seal Enforcement
# ---------------------------------------------------------

def test_sealed_family_rejects_new_versions():
    registry = _setup_registry()

    registry.seal_family("ROOT_POLICY")

    with pytest.raises(Exception):
        registry.add_policy(
            policy_family="ROOT_POLICY",
            version=2,
            effective_from="2026-02-01T00:00:00Z",
            minimum_weight=5,
        )
