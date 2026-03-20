from typing import Set


class PolicyRevocationRegistry:
    """
    Immutable append-only policy revocation registry.

    This registry exists in memory for Track A+.

    In future Track D, this can be anchored.
    """

    def __init__(self, revoked_versions: Set[str] = None):
        self._revoked = frozenset(revoked_versions or set())

    def is_revoked(self, policy_version: str) -> bool:
        return policy_version in self._revoked

    def with_revocation(self, policy_version: str):
        """
        Append-only mutation — returns new registry.
        """
        new_set = set(self._revoked)
        new_set.add(policy_version)
        return PolicyRevocationRegistry(new_set)

    @property
    def revoked_versions(self):
        return self._revoked
