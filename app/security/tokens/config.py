import os
from datetime import timedelta


class TokenConfig:
    """
    Central configuration for authentication JWTs.
    """

    SECRET_KEY = os.getenv(
        "JWT_SECRET_KEY",
        "CHANGE_ME_IN_PRODUCTION",
    )

    ALGORITHM = "HS256"

    ISSUER = "meika-secure-id"

    AUDIENCE = "meika-api"

    ACCESS_TOKEN_TTL = timedelta(hours=1)