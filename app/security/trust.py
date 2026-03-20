# app/security/trust.py

from app.security.errors import SecurityPipelineError
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
        raise SecurityPipelineError("Device cloning detected")

    if getattr(device, "compromised", False):
        raise SecurityPipelineError("Device compromised")
