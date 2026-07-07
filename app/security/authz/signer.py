import jwt

from .constants import DEFAULT_ALGORITHM
from .key_provider import KeyProvider

class TokenSigner:

    @staticmethod
    def sign(claims: dict) -> str:
        return jwt.encode(
            claims,
            KeyProvider.signing_key(),
            algorithm=DEFAULT_ALGORITHM,
        )

    @staticmethod
    def sign(
        claims: dict,
    ) -> str:

        return jwt.encode(
            claims,
            TokenSigner.SECRET,
            algorithm=DEFAULT_ALGORITHM,
        )