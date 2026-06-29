from app.security.governance.policy_revocation import (
    PolicyRevocationRegistry,
)


def test_empty_registry():
    registry = PolicyRevocationRegistry()

    assert registry.revoked_versions == frozenset()


def test_is_revoked_false():
    registry = PolicyRevocationRegistry(
        {"1.0.0"}
    )

    assert registry.is_revoked(
        "2.0.0"
    ) is False


def test_is_revoked_true():
    registry = PolicyRevocationRegistry(
        {"1.0.0"}
    )

    assert registry.is_revoked(
        "1.0.0"
    ) is True


def test_with_revocation_returns_new_registry():
    registry = PolicyRevocationRegistry()

    updated = registry.with_revocation(
        "1.0.0"
    )

    assert updated is not registry
    assert updated.is_revoked("1.0.0")


def test_original_registry_unchanged():
    registry = PolicyRevocationRegistry()

    updated = registry.with_revocation(
        "1.0.0"
    )

    assert registry.is_revoked(
        "1.0.0"
    ) is False

    assert updated.is_revoked(
        "1.0.0"
    ) is True