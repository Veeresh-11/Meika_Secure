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
    """
    Validate an authentication JWT.
    """

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

        # Validate issuer only if present
        if "iss" in payload:
            if payload["iss"] != TokenConfig.ISSUER:
                raise SecurityError("Invalid issuer")

        # Validate audience only if present
        if "aud" in payload:
            if payload["aud"] != TokenConfig.AUDIENCE:
                raise SecurityError("Invalid audience")

    except jwt.ExpiredSignatureError:
        raise SecurityError("Token expired")

    except jwt.InvalidTokenError:
        raise SecurityError("Invalid token")

    expected_dkh = hashlib.sha256(
        device_public_key
    ).hexdigest()

    if payload.get("dkh") != expected_dkh:
        raise SecurityError(
            "Token not bound to this device"
        )

    return payload