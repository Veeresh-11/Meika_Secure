from __future__ import annotations
from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class AnchorPolicy:
    """
    Constitutional Anchor Policy

    - version: governance-controlled version
    - required_networks: networks that MUST appear in receipts
    - minimum_total: minimum total number of receipts required
    - allowed_networks: whitelist of valid networks
    """

    version: int
    required_networks: List[str]
    minimum_total: int
    allowed_networks: List[str]

    def validate_structure(self) -> None:
        if self.version <= 0:
            raise ValueError("Policy version must be positive")

        if self.minimum_total <= 0:
            raise ValueError("minimum_total must be positive")

        if not self.allowed_networks:
            raise ValueError("allowed_networks cannot be empty")

        if not set(self.required_networks).issubset(set(self.allowed_networks)):
            raise ValueError("Required networks must be subset of allowed networks")

        if self.minimum_total < len(self.required_networks):
            raise ValueError(
                "minimum_total cannot be less than required networks count"
            )
