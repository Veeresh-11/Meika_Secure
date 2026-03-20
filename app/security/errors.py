"""
TRACK_A_CORE — Security Failure Semantics

This module defines how security failures are classified and propagated
inside the Security Kernel (Track A).

Key principles:
- Expected security failures result in deterministic DENY decisions.
- Misuse or invalid security input raises SecurityError.
- Non-recoverable system corruption raises SecurityInvariantViolation.
"""

from enum import Enum
from app.security.results import DenyReason


class FailureClass(str, Enum):
    """
    High-level classification of why a security evaluation failed.
    """
    CONTEXT = "context"
    AUTH = "authentication"
    GRANT = "grant"
    POLICY = "policy"
    EVIDENCE = "evidence"
    TIME = "time"
    HARDWARE = "hardware"

    # Required for device precedence and Track A determinism
    DEVICE = "device"


class SecurityPipelineError(Exception):
    """
    Deterministic, expected security failure.

    Used internally to short-circuit evaluation and MUST be converted
    into a DENY SecurityDecision by the pipeline.
    """

    def __init__(self, reason: DenyReason, failure_class: FailureClass):
        self.reason = reason
        self.failure_class = failure_class
        super().__init__(f"{failure_class.value}: {reason.value}")


class SecurityError(Exception):
    """
    Invalid or unsafe security input or usage.

    Raised when a caller violates a required security invariant
    (e.g., malformed token, missing binding, invalid proof).

    This is NOT a decision and MUST NOT be treated as authority.
    """
    pass


class SecurityInvariantViolation(Exception):
    """
    Non-recoverable system invariant violation.

    Raised when the system enters an impossible or unsafe state.
    Must fail closed immediately.
    """
    pass
