import jwt
import hashlib
from datetime import datetime, timedelta

SECRET = "dev-secret-change-later"
ALGO = "HS256"


def hash_public_key(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()


def issue_device_bound_token(
    *,
    user_id: str,
    device_id: str,
    device_public_key: bytes,
    ttl_minutes: int = 5,
) -> str:
    payload = {
        "sub": user_id,
        "did": device_id,
        "dkh": hash_public_key(device_public_key),
        "exp": datetime.utcnow() + timedelta(minutes=ttl_minutes),
    }
    return jwt.encode(payload, SECRET, algorithm=ALGO)
