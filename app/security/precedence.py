"""
TRACK_A_CORE — Absolute Precedence Guard

This module enforces *constitutional* device hard-stops that prevent
any further evaluation of a request.

Purpose:
- Decide whether a request is even eligible for evaluation
- Enforce dominance rules that no policy, grant, or risk may override

This runs BEFORE:
- Device trust posture checks
- Grant enforcement
- Policy evaluation
"""

from typing import Optional

from app.security.device_snapshot import DeviceSnapshot
from app.security.errors import SecurityPipelineError, FailureClass
from app.security.results import DenyReason


class PrecedenceGuard:
    """
    Enforces absolute dominance rules.

    These checks answer:
    "Does this request have the right to be evaluated at all?"
    """

    @staticmethod
    def enforce(device: Optional[DeviceSnapshot]) -> None:
        if device is None:
            return

        # 1. Clone dominates everything
        if device.clone_confirmed:
            raise SecurityPipelineError(
                DenyReason.DEVICE_CLONED,
                FailureClass.DEVICE,
            )

        # 2. Registration beats state and posture
        if not device.registered:
            raise SecurityPipelineError(
                DenyReason.DEVICE_NOT_REGISTERED,
                FailureClass.DEVICE,
            )

        # 3. Revocation / loss is terminal
        if device.state in ("revoked", "lost"):
            raise SecurityPipelineError(
                DenyReason.DEVICE_REVOKED,
                FailureClass.DEVICE,
            )

        # 4. Known compromise blocks evaluation
        if device.compromised:
            raise SecurityPipelineError(
                DenyReason.DEVICE_COMPROMISED,
                FailureClass.DEVICE,
            )
