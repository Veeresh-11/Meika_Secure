"""
TRACK_A_CORE — Security Result Vocabulary

This module defines the canonical vocabulary used by the Security Kernel
(Track A) to explain *why* a decision was made.

This file contains:
- Enumerated DENY reasons (no magic strings)
- Passive result classification labels
- A NON-AUTHORITATIVE PolicyResult shape (Track-B produced, Track-A sanitized)

IMPORTANT BOUNDARY RULES:
- This module contains NO enforcement logic.
- This module confers NO authority.
- SecurityDecision is the ONLY authoritative decision object.
- PolicyResult is advisory input ONLY and MUST be adapted or rejected.
"""

from enum import Enum
from dataclasses import dataclass
from datetime import datetime
from app.security.decision import DecisionOutcome


class DenyReason(str, Enum):
    """
    Canonical reasons for DENY decisions.
    """

    # ---- Context / Authentication ----
    MISSING_CONTEXT = "Missing security context"
    UNAUTHENTICATED = "Unauthenticated request"

    # ---- Snapshot / Time ----
    SNAPSHOT_EXPIRED = "Snapshot expired"

    # ---- Grant enforcement ----
    EXPIRED_GRANT = "Grant expired"
    GRANT_SCOPE_MISMATCH = "Grant scope mismatch"

    # ---- Evidence invariants ----
    MISSING_EVIDENCE = "Decision missing evidence"

    # ---- Device trust hard-stops ----
    DEVICE_CLONED = "Device cloning detected"
    DEVICE_COMPROMISED = "Device integrity compromised"
    DEVICE_NOT_REGISTERED = "Device not registered"
    DEVICE_REVOKED = "Device revoked or lost"
    DEVICE_NOT_HARDWARE_BACKED = "Device key not hardware-backed"
    DEVICE_ATTESTATION_FAILED = "Device attestation failed"
    DEVICE_BINDING_INVALID = "Device identity binding invalid"
    DEVICE_INSECURE_BOOT = "Device secure boot not verified"

    # ---- Policy interaction ----
    POLICY_INVALID_RESULT = "Policy returned invalid decision"
    POLICY_DENY = "Denied by policy"

    # ---- Safety fallback ----
    DEFAULT_DENY = "Default deny"


class ResultKind(str, Enum):
    """
    Classification of *advisory* results.

    These labels describe the origin of a recommendation but carry
    NO enforcement authority at the kernel layer.
    """
    POLICY = "policy"
    RISK = "risk"
    GRANT = "grant"
    CONTAINMENT = "containment"


@dataclass(frozen=True)
class PolicyResult:
    """
    TRACK-B ADVISORY TYPE — NOT AUTHORITATIVE

    This object may be produced by policy or risk engines (Track B)
    and passed to the kernel for evaluation.

    The kernel MUST:
    - Sanitize this input
    - Adapt it into a SecurityDecision, or
    - Reject it with a DENY

    PolicyResult MUST NEVER be enforced directly.
    """
    outcome: DecisionOutcome
    policy_version: str
    evaluated_at: datetime
    kind: ResultKind
    reason: str
