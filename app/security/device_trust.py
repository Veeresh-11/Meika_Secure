"""
TRACK_A_CORE — Device Trust Enforcement

This module enforces absolute device hard-stops based on a frozen
DeviceSnapshot.

Design principles:
- Device trust is evaluated BEFORE policy and grants
- First failure wins (strict precedence)
- No side effects, no mutation, no recovery
- Results are deterministic and auditable
"""

from app.security.device_snapshot import DeviceSnapshot
from app.security.errors import SecurityPipelineError, FailureClass
from app.security.results import DenyReason


class DeviceTrustEvaluator:
    """
    Converts device posture into canonical DENY reasons.

    This evaluator represents *law*, not policy.
    """

    @staticmethod
    def enforce(device: DeviceSnapshot) -> None:
        # ---- Absolute identity failures ----
        if device.clone_confirmed:
            raise SecurityPipelineError(
                DenyReason.DEVICE_CLONED,
                FailureClass.DEVICE,
            )

        if not device.registered:
            raise SecurityPipelineError(
                DenyReason.DEVICE_NOT_REGISTERED,
                FailureClass.DEVICE,
            )

        if device.state in ("revoked", "lost"):
            raise SecurityPipelineError(
                DenyReason.DEVICE_REVOKED,
                FailureClass.DEVICE,
            )

        # ---- Integrity failures ----
        if device.compromised:
            raise SecurityPipelineError(
                DenyReason.DEVICE_COMPROMISED,
                FailureClass.DEVICE,
            )

        # ---- Hardware & binding guarantees ----
        if not device.hardware_backed:
            raise SecurityPipelineError(
                DenyReason.DEVICE_NOT_HARDWARE_BACKED,
                FailureClass.DEVICE,
            )

        if not device.attestation_verified:
            raise SecurityPipelineError(
                DenyReason.DEVICE_ATTESTATION_FAILED,
                FailureClass.DEVICE,
            )

        if not device.binding_valid:
            raise SecurityPipelineError(
                DenyReason.DEVICE_BINDING_INVALID,
                FailureClass.DEVICE,
            )

        # ---- Replay safety ----
        if device.replay_detected:
            raise SecurityPipelineError(
                DenyReason.DEFAULT_DENY,
                FailureClass.DEVICE,
            )
