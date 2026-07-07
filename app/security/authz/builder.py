from app.db.grant_models import Grant

from .claims import ClaimsBuilder
from .signer import TokenSigner


class TokenBuilder:

    @staticmethod
    def build_access_token(
        grant: Grant,
    ) -> str:

        claims = ClaimsBuilder.build(grant)

        return TokenSigner.sign(claims)