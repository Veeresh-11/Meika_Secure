"""
TRACK D — Policy-Bound Quorum

Defines governance rules for threshold verification.

Security Guarantees:
- Required role enforcement
- Minimum weight enforcement
- Payload-type binding (optional)
"""

from __future__ import annotations
from typing import List, Optional


class QuorumPolicy:

    def __init__(
        self,
        *,
        required_roles: Optional[List[str]] = None,
        minimum_weight: int = 1,
        payload_type: Optional[str] = None,
    ):
        if minimum_weight <= 0:
            raise ValueError("minimum_weight must be positive")

        self.required_roles = required_roles or []
        self.minimum_weight = minimum_weight
        self.payload_type = payload_type

    def validate(
        self,
        *,
        collected_roles: List[str],
        total_weight: int,
        payload: dict,
    ) -> None:
        """
        Raises exception if quorum policy is violated.
        """

        # Weight enforcement
        if total_weight < self.minimum_weight:
            raise ValueError("Insufficient quorum weight")

        # Role enforcement
        for role in self.required_roles:
            if role not in collected_roles:
                raise ValueError(f"Missing required role: {role}")

        # Optional payload-type enforcement
        if self.payload_type:
            if payload.get("type") != self.payload_type:
                raise ValueError("Payload type not authorized for this quorum policy")
