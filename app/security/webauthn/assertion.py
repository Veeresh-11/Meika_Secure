"""Legacy assertion shim.

A signature counter alone does not authenticate a WebAuthn assertion. Use
app.security.webauthn.fido2.verify_authentication to validate the client data,
RP ID hash, user-presence/user-verification flags, and signature.
"""
from __future__ import annotations


class AssertionVerificationError(ValueError):
    """Raised when an assertion cannot be cryptographically verified."""


def verify_assertion(assertion: dict, cred) -> None:
    """Reject the legacy counter-only assertion format."""
    raise AssertionVerificationError(
        "Legacy counter-only assertion is disabled; use FIDO2 signature verification"
    )
