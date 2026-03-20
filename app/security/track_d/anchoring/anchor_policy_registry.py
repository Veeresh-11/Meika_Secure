from __future__ import annotations

import json
import hashlib
from typing import List, Dict, Optional

from .anchor_policy_engine import AnchorPolicy


def _canonical(data: dict) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _hash(data: dict) -> str:
    return hashlib.sha256(_canonical(data)).hexdigest()


class AnchorPolicyRegistry:

    def __init__(self):
        self._policies: List[Dict] = []

    # -----------------------------------------------------

    def register(self, policy: AnchorPolicy) -> None:

        if policy.version <= 0:
            raise ValueError("Policy version must be positive")

        if policy.minimum_total <= 0:
            raise ValueError("minimum_total must be positive")

        if not policy.allowed_networks:
            raise ValueError("allowed_networks cannot be empty")

        if self._policies:

            latest = self._policies[-1]

            if policy.version <= latest["version"]:
                raise ValueError("Policy version must strictly increase")

            if policy.minimum_total < latest["minimum_total"]:
                raise ValueError("Policy downgrade detected (minimum_total)")

            if not set(policy.allowed_networks).issuperset(
                set(latest["allowed_networks"])
            ):
                raise ValueError("Policy downgrade detected (allowed_networks)")

        entry = policy.to_dict()
        entry["policy_hash"] = policy.policy_hash

        self._policies.append(entry)

    # -----------------------------------------------------
    # Return AnchorPolicy OBJECT (not dict)
    # -----------------------------------------------------

    def latest(self) -> Optional[AnchorPolicy]:

        if not self._policies:
            return None

        data = self._policies[-1]

        return AnchorPolicy(
            version=data["version"],
            minimum_total=data["minimum_total"],
            allowed_networks=data["allowed_networks"],
            required_networks=data["required_networks"],
        )

    # -----------------------------------------------------

    def latest_hash(self) -> Optional[str]:

        if not self._policies:
            return None

        return self._policies[-1]["policy_hash"]

    # -----------------------------------------------------

    def get(self, version: int) -> Optional[Dict]:

        for entry in self._policies:
            if entry["version"] == version:
                return dict(entry)

        return None

    # -----------------------------------------------------

    def snapshot(self) -> List[Dict]:
        return [dict(e) for e in self._policies]

    # -----------------------------------------------------

    def validate(self) -> bool:

        previous_version = 0

        for entry in self._policies:

            if entry["version"] <= previous_version:
                raise ValueError("Policy version ordering violated")

            data = {
                "version": entry["version"],
                "minimum_total": entry["minimum_total"],
                "allowed_networks": sorted(entry["allowed_networks"]),
                "required_networks": sorted(entry["required_networks"]),
            }

            if _hash(data) != entry["policy_hash"]:
                raise ValueError("Policy tampering detected")

            previous_version = entry["version"]

        return True
