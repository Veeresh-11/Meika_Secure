import jwt
import hashlib
from app.security.errors import SecurityError

SECRET = "dev-secret-change-later"
ALGO = "HS256"


def enforce_device_bound_token(token: str, device_public_key: bytes):
    try:
        payload = jwt.decode(token, SECRET, algorithms=[ALGO])
    except jwt.ExpiredSignatureError:
        raise SecurityError("Token expired")
    except jwt.InvalidTokenError:
        raise SecurityError("Invalid token")

    expected_dkh = hashlib.sha256(device_public_key).hexdigest()

    if payload["dkh"] != expected_dkh:
        raise SecurityError("Token not bound to this device")

    return payload
