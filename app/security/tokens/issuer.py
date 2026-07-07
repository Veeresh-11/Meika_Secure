import hashlib
from datetime import datetime, timedelta

import jwt
import os
from app.security.tokens.config import TokenConfig


# ------------------------------------------------------------------
# Backward compatibility
# ------------------------------------------------------------------

SECRET = os.getenv(
    "JWT_SECRET_KEY",
    "meika-secure-id-development-secret-key-2026",
)
ALGO = TokenConfig.ALGORITHM

def hash_public_key(public_key: bytes) -> str:
    """
    Produce a deterministic hash of the device public key.
    """
    return hashlib.sha256(public_key).hexdigest()


def issue_device_bound_token(
    *,
    user_id: str,
    device_id: str,
    device_public_key: bytes,
    session_id: str | None = None,
    jwt_id: str | None = None,
    ttl_minutes: int | None = None,
) -> str:

    now = datetime.utcnow()

    if ttl_minutes is None:
        exp = now + TokenConfig.ACCESS_TOKEN_TTL
    else:
        exp = now + timedelta(minutes=ttl_minutes)

    payload = {
        "iss": TokenConfig.ISSUER,
        "aud": TokenConfig.AUDIENCE,
        "sub": user_id,
        "did": device_id,
        "dkh": hash_public_key(device_public_key),
        "iat": now,
        "exp": exp,
    }

    if session_id is not None:
        payload["sid"] = session_id

    if jwt_id is not None:
        payload["jti"] = jwt_id

    return jwt.encode(
        payload,
        SECRET,
        algorithm= ALGO,
    )