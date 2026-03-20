from datetime import datetime
from .models import WebAuthnCredential

def verify_assertion(assertion: dict, cred: WebAuthnCredential):
    if cred.revoked:
        raise ValueError("Credential revoked")

    # FIDO2 canonical clone detection
    if assertion["sign_count"] <= cred.sign_count:
        cred.revoked = True
        raise ValueError("Clone detected (sign counter regression)")

    cred.sign_count = assertion["sign_count"]
    cred.last_used_at = datetime.utcnow()
