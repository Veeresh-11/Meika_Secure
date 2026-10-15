from datetime import datetime, timezone
from .models import WebAuthnCredential


class CredentialCloneDetected(ValueError):
    """Raised when an authenticator sign counter indicates a cloned credential."""

def verify_assertion(assertion: dict, cred: WebAuthnCredential):
    if cred.revoked:
        raise ValueError("Credential revoked")

    # FIDO2 canonical clone detection
    if assertion["sign_count"] <= cred.sign_count:
        cred.revoked = True
        raise CredentialCloneDetected("Clone detected (sign counter regression)")

    cred.sign_count = assertion["sign_count"]
    cred.last_used_at = datetime.now(timezone.utc).replace(tzinfo=None)
