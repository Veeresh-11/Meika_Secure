import hashlib

from app.security.tokens.issuer import issue_device_bound_token


class TokenService:
    """
    High-level interface for issuing authentication tokens.
    """

    @staticmethod
    def issue_access_token(
        *,
        grant,
        device_public_key: bytes,
) -> str:

     return issue_device_bound_token(
        user_id=str(grant.user_id),
        session_id=str(grant.id),
        jwt_id=str(grant.jwt_id),
        device_id=str(grant.device_id or ""),
        device_public_key=device_public_key,
    )
    
    @staticmethod
    def hash_public_key(
        public_key: bytes,
    ) -> str:

        return hashlib.sha256(public_key).hexdigest()