from app.db.grant_models import Grant

from .constants import (
    TOKEN_VERSION,
    ISSUER,
    AUDIENCE,
)


class ClaimsBuilder:

    @staticmethod
    def build(
        grant: Grant,
    ) -> dict:

        return {
            "ver": TOKEN_VERSION,
            "sub": str(grant.user_id),
            "sid": str(grant.session_id),
            "cid": str(grant.credential_id),
            "gid": str(grant.id),
            "jti": str(grant.jwt_id),
            "typ": grant.grant_type,
            "iat": int(grant.issued_at.timestamp()),
            "exp": int(grant.expires_at.timestamp()),
            "iss": ISSUER,
            "aud": AUDIENCE,
            "did": (
                str(grant.device_id)
                if grant.device_id
                else None
            ),
        }