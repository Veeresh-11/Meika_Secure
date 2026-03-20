# app/security/policy/models.py

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any


class PolicyEffect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    RESTRICT = "restrict"


@dataclass(frozen=True)
class PolicyRule:
    """
    Single policy rule.
    """
    name: str
    effect: PolicyEffect
    when: Dict[str, Any]
    reason: str


@dataclass(frozen=True)
class PolicyDocument:
    """
    Immutable policy bundle.
    """
    version: str
    rules: tuple[PolicyRule, ...]

