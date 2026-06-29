# app/security/trust.py

from app.security.errors import (
    SecurityPipelineError,
    FailureClass,
)
from app.security.results import DenyReason
from app.security.context import SecurityContext


def enforce_trust(context: SecurityContext) -> None:
    """
    Sprint A2 trust enforcement.
    Hard-stop checks. No policy allowed after failure.
    """

    device = getattr(context, "device", None)

    if device is None:
        return

    if (
        getattr(device, "clone_confirmed", False)
        or getattr(device, "clone_detected", False)
        or getattr(device, "is_clone", False)
        or getattr(device, "state", None) == "cloned"
    ):
        raise SecurityPipelineError(
            DenyReason.DEVICE_CLONED,
            FailureClass.DEVICE,
        )

    if getattr(device, "compromised", False):
        raise SecurityPipelineError(
            DenyReason.DEVICE_COMPROMISED,
            FailureClass.DEVICE,
        )