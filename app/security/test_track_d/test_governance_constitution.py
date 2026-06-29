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

def test_invalid_timestamp():

    registry = GovernanceRegistry()

    with pytest.raises(ValueError):
        registry.add_policy(
            policy_family="CORE",
            version=1,
            effective_from="bad",
            minimum_weight=1,
        )
        
def test_invalid_version():

    registry = GovernanceRegistry()

    with pytest.raises(ValueError):
        registry.add_policy(
            policy_family="CORE",
            version=0,
            effective_from="2025-01-01T00:00:00Z",
            minimum_weight=1,
        )
        
def test_invalid_weight():

    registry = GovernanceRegistry()

    with pytest.raises(ValueError):
        registry.add_policy(
            policy_family="CORE",
            version=1,
            effective_from="2025-01-01T00:00:00Z",
            minimum_weight=0,
        )
        
def test_policy_already_expired():

    registry = GovernanceRegistry()

    registry.add_policy(
        policy_family="CORE",
        version=1,
        effective_from="2025-01-01T00:00:00Z",
        minimum_weight=1,
    )

    registry.expire_policy(
        "CORE",
        1,
        "2025-06-01T00:00:00Z",
    )

    with pytest.raises(ValueError):
        registry.expire_policy(
            "CORE",
            1,
            "2025-07-01T00:00:00Z",
        )
        
def test_seal_unknown_family():

    registry = GovernanceRegistry()

    with pytest.raises(ValueError):
        registry.seal_family("UNKNOWN")
        
def test_validate_chain_version_violation():

    registry = GovernanceRegistry()

    registry.add_policy(
        policy_family="CORE",
        version=1,
        effective_from="2025-01-01T00:00:00Z",
        minimum_weight=1,
    )

    registry.add_policy(
        policy_family="CORE",
        version=2,
        effective_from="2025-02-01T00:00:00Z",
        minimum_weight=1,
    )

    registry._families["CORE"][1]["version"] = 1

    with pytest.raises(ValueError):
        registry.validate_chain("CORE")
        
def test_get_policy_not_found():

    registry = GovernanceRegistry()

    registry.add_policy(
        policy_family="CORE",
        version=1,
        effective_from="2025-01-01T00:00:00Z",
        minimum_weight=1,
    )

    with pytest.raises(ValueError):
        registry.get_policy("CORE", 2)
        
def test_get_active_policy():

    registry = GovernanceRegistry()

    registry.add_policy(
        policy_family="CORE",
        version=1,
        effective_from="2025-01-01T00:00:00Z",
        minimum_weight=1,
    )

    registry.add_policy(
        policy_family="CORE",
        version=2,
        effective_from="2025-02-01T00:00:00Z",
        minimum_weight=1,
    )

    active = registry.get_active_policy(
        policy_family="CORE",
        at_timestamp="2025-03-01T00:00:00Z",
    )

    assert active["version"] == 2
    
def test_get_active_policy_none():

    registry = GovernanceRegistry()

    assert registry.get_active_policy(
        policy_family="CORE",
        at_timestamp="2025-01-01T00:00:00Z",
    ) is None
    
def test_get_latest_policy():

    registry = GovernanceRegistry()

    registry.add_policy(
        policy_family="CORE",
        version=1,
        effective_from="2025-01-01T00:00:00Z",
        minimum_weight=1,
    )

    latest = registry.get_latest_policy("CORE")

    assert latest["version"] == 1
    
def test_get_latest_policy_none():

    registry = GovernanceRegistry()

    assert registry.get_latest_policy("CORE") is None
    
from app.security.track_d.governance.governance_registry import _hash

def test_validate_chain_version_violation():

    registry = GovernanceRegistry()

    registry.add_policy(
        policy_family="CORE",
        version=1,
        effective_from="2025-01-01T00:00:00Z",
        minimum_weight=1,
    )

    registry.add_policy(
        policy_family="CORE",
        version=2,
        effective_from="2025-02-01T00:00:00Z",
        minimum_weight=1,
    )

    second = registry._families["CORE"][1]

    second["version"] = 1

    # recompute entry hash
    entry = dict(second)
    entry.pop("entry_hash")

    second["entry_hash"] = _hash(entry)

    with pytest.raises(ValueError, match="Version ordering violation"):
        registry.validate_chain("CORE")
        
def test_get_active_policy_middle_of_history():

    registry = GovernanceRegistry()

    registry.add_policy(
        policy_family="CORE",
        version=1,
        effective_from="2025-01-01T00:00:00Z",
        minimum_weight=1,
    )

    registry.add_policy(
        policy_family="CORE",
        version=2,
        effective_from="2025-03-01T00:00:00Z",
        minimum_weight=1,
    )

    active = registry.get_active_policy(
        policy_family="CORE",
        at_timestamp="2025-02-01T00:00:00Z",
    )

    assert active["version"] == 1