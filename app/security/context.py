"""
TRACK_A_CORE — SecurityContext

This file defines the immutable input to the SecurityPipeline.

SecurityContext represents a fully-normalized, frozen snapshot of all
information required to make a deterministic security decision.

Key guarantees:
- Immutable (frozen dataclass)
- No side effects
- No I/O
- No evidence creation
- Safe to hash and serialize

If information is not present in SecurityContext, it MUST NOT influence
authorization decisions in Track-A.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional

from app.security.device_snapshot import DeviceSnapshot
from app.security.grants.models import Grant


@dataclass(frozen=True)
class SecurityContext:
    """
    Immutable security decision input.

    This object is passed unchanged through the entire Track-A pipeline.
    Any mutation attempt is a security error by design.
    """

    request_id: str
    principal_id: str
    intent: str
    authenticated: bool
    device_id: Optional[str]
    device: Optional[DeviceSnapshot]
    risk_signals: Dict
    request_time: datetime
    metadata: Dict
    grant: Optional[Grant] = None

    def __post_init__(self):
        # Enforce snapshot semantics explicitly
        if self.device is not None and not isinstance(self.device, DeviceSnapshot):
            raise TypeError("device must be DeviceSnapshot")

    # -------------------------------------------------
    # TEST HELPERS (TEST-ONLY — NEVER USED IN PROD)
    # -------------------------------------------------

    @classmethod
    def fake_allow_context(cls):
        """
        Create a minimal authenticated context with no device or grant.

        IMPORTANT:
        - NEVER attach a Grant here
        - Grants must be explicitly constructed in tests
        """
        return cls(
            request_id="allow",
            principal_id="user",
            intent="authentication.attempt",
            authenticated=True,
            device_id=None,
            device=None,
            risk_signals={},
            request_time=datetime.utcnow(),
            metadata={},
            grant=None,
        )

    @classmethod
    def fake_deny_context(cls):
        """
        Alias for fake_allow_context.

        DENY is a decision outcome, not a context property.
        """
        return cls.fake_allow_context()

    @classmethod
    def fake_device(cls, **device_flags):
        """
        Create a context with a synthetic DeviceSnapshot.

        Used to test precedence and device trust invariants.
        """
        DEFAULTS = {
            "registered": True,
            "state": "active",
            "compromised": False,
            "clone_confirmed": False,
            "hardware_backed": True,
            "attestation_verified": True,
            "binding_valid": True,
            "secure_boot": True,
            "replay_detected": False,
        }

        data = DEFAULTS.copy()
        data.update(device_flags)

        snapshot = DeviceSnapshot(
            device_id="test-device",
            **data,
        )

        return cls(
            request_id="test-device",
            principal_id="user",
            intent="authentication.attempt",
            authenticated=True,
            device_id="test-device",
            device=snapshot,
            risk_signals={},
            request_time=datetime.utcnow(),
            metadata={},
            grant=None,
        )

    @classmethod
    def fake_device_revoked(cls):
        """
        Convenience helper for revoked-device scenarios.
        """
        return cls.fake_device(state="revoked")

    # -------------------------------------------------
    # SAFE SERIALIZATION
    # -------------------------------------------------

    def to_dict(self) -> Dict:
        """
        Deterministic, side-effect-free serialization.

        Used for:
        - Context hashing
        - Evidence generation (Track-B)
        - Auditing
        """
        return {
            "request_id": self.request_id,
            "principal_id": self.principal_id,
            "intent": self.intent,
            "authenticated": self.authenticated,
            "device_id": self.device_id,
            "device": self.device.to_dict() if self.device else None,
            "risk_signals": self.risk_signals,
            "request_time": self.request_time.isoformat(),
            "metadata": self.metadata,
            "grant": self.grant.to_dict() if self.grant else None,
        }
