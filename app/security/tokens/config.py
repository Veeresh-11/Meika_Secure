from datetime import timedelta

from app.config.settings import settings


class TokenConfig:
    """Central configuration for authentication JWTs."""

    # No development fallback: application startup requires JWT_SECRET_KEY
    # from the process environment or the ignored local .env file.
    SECRET_KEY = settings.jwt_secret_key
    ALGORITHM = "HS256"
    ISSUER = "meika-secure-id"
    AUDIENCE = "meika-api"
    ACCESS_TOKEN_TTL = timedelta(hours=1)
