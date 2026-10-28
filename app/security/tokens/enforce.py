import hashlib

import jwt

from app.security.errors import SecurityError
from app.security.tokens.config import TokenConfig

# ------------------------------------------------------------------
# Backward compatibility
# ------------------------------------------------------------------

SECRET = TokenConfig.SECRET_KEY
ALGO = TokenConfig.ALGORITHM


def enforce_device_bound_token(
    token: str,
    device_public_key: bytes,
):
    """Validate a signed JWT against a registered device public key."""
    if not isinstance(device_public_key, bytes) or not device_public_key:
        raise SecurityError("Invalid device public key")

    try:
        payload = jwt.decode(
            token,
            SECRET,
            algorithms=[ALGO],
            options={
                "verify_aud": False,
                "verify_iss": False,
            },
        )

        # Issuer and audience are mandatory trust boundaries.
        if payload.get("iss") != TokenConfig.ISSUER:
            raise SecurityError("Invalid issuer")

        if payload.get("aud") != TokenConfig.AUDIENCE:
            raise SecurityError("Invalid audience")

    except jwt.ExpiredSignatureError:
        raise SecurityError("Token expired")

    except jwt.InvalidTokenError:
        raise SecurityError("Invalid token")

    expected_dkh = hashlib.sha256(device_public_key).hexdigest()
    if payload.get("dkh") != expected_dkh:
        raise SecurityError("Token not bound to this device")

    return payload
