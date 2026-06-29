# app/security/policy/evaluators/device.py

from app.security.context import SecurityContext
from app.security.policy.models import PolicyRule


def match_device(rule: PolicyRule, ctx: SecurityContext) -> bool:
    """
    Match device-related policy conditions against the current DeviceContext model.
    """

    device = ctx.device

    # If policy refers to device.* but no device is present → no match
    if device is None:
        # Explicit deny rules like `device.registered: false` must still match
        if any(k.startswith("device.") for k in rule.when.keys()):
            return False
        return True

    for key, expected in rule.when.items():

     if not key.startswith("device."):
        continue

     if key == "device.registered":
        if device.registered != expected:
            return False

     elif key == "device.state":
        if device.state != expected:
            return False

     elif key.startswith("device.identity."):
        attr = key.split(".", 2)[2]
        if getattr(device.identity, attr) != expected:
            return False

     elif key.startswith("device.posture."):
        attr = key.split(".", 2)[2]
        if getattr(device.posture, attr) != expected:
            return False

     else:
        return False

    return True