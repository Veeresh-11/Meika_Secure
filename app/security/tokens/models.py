from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class AccessTokenClaims:
    """
    Strongly typed representation of an authentication JWT.
    """

    subject: str

    session_id: str

    jwt_id: str

    device_id: str | None

    device_key_hash: str

    issuer: str

    audience: str

    issued_at: datetime

    expires_at: datetime