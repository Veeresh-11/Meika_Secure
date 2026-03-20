from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass, field
from typing import List, Iterable


# =========================================================
# Deterministic Hash Utilities
# =========================================================

def _canonical(data: dict) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _hash(data: dict) -> str:
    return hashlib.sha256(_canonical(data)).hexdigest()


# =========================================================
# Anchor Policy
# =========================================================

@dataclass(frozen=True)
class AnchorPolicy:
    """
    Immutable constitutional anchor policy.
    """

    version: int
    minimum_total: int
    allowed_networks: List[str]
    required_networks: List[str] = field(default_factory=list)

    # -----------------------------------------------------

    def __post_init__(self):
        # If required_networks not provided, default to allowed_networks
        if not self.required_networks:
            object.__setattr__(
                self,
                "required_networks",
                list(self.allowed_networks),
            )

    # -----------------------------------------------------
    # Deterministic Serialization
    # -----------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "minimum_total": self.minimum_total,
            "allowed_networks": sorted(self.allowed_networks),
            "required_networks": sorted(self.required_networks),
        }

    # -----------------------------------------------------
    # Constitutional Hash
    # -----------------------------------------------------

    @property
    def policy_hash(self) -> str:
        return _hash(self.to_dict())

    # -----------------------------------------------------
    # Dict-style compatibility (for registry tests)
    # -----------------------------------------------------

    def __getitem__(self, key):
        return getattr(self, key)


# =========================================================
# Anchor Policy Engine
# =========================================================

class AnchorPolicyEngine:

    def __init__(self, policy: AnchorPolicy):
        self.policy = policy

    def evaluate(self, receipts: Iterable) -> bool:

        receipts = list(receipts)

        if len(receipts) < self.policy.minimum_total:
            return False

        networks = {r.network for r in receipts}

        if not networks.issubset(set(self.policy.allowed_networks)):
            return False

        if not set(self.policy.required_networks).issubset(networks):
            return False

        return True
