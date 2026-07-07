import jwt

from .constants import (
    DEFAULT_ALGORITHM,
    AUDIENCE,
    ISSUER,
    TOKEN_VERSION,
)
from .key_provider import KeyProvider


class TokenValidator:
    """
    Validates Meika Authorization JWTs.

    Performs:

    • Signature validation
    • Issuer validation
    • Audience validation
    • Expiration validation
    • Required claims validation
    • Token version validation
    """

    REQUIRED_CLAIMS = {
        "ver",
        "sub",
        "sid",
        "cid",
        "gid",
        "jti",
        "typ",
        "iat",
        "exp",
        "iss",
        "aud",
    }

    @staticmethod
    def validate(
        token: str,
    ) -> dict:

        payload = jwt.decode(
            token,
            KeyProvider.signing_key(),
            algorithms=[DEFAULT_ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER,
        )

        # ------------------------------------------
        # Required Claims Validation
        # ------------------------------------------

        missing = (
            TokenValidator.REQUIRED_CLAIMS
            - payload.keys()
        )

        if missing:
            raise ValueError(
                f"Missing JWT claims: {sorted(missing)}"
            )

        # ------------------------------------------
        # Token Version Validation
        # ------------------------------------------

        if payload["ver"] != TOKEN_VERSION:
            raise ValueError(
                f"Unsupported token version: {payload['ver']}"
            )

        return payload