from app.db.grant_models import Grant
from app.security.tokens.issuer import issue_device_bound_token
from app.services.grant_service import GrantService

class TokenService:
    """
    Issues JWT access tokens from persisted Authorization Grants.

    TokenService acts as the application-layer bridge between
    the Authorization Engine and the JWT issuer.

    Future responsibilities:
        • Refresh Tokens
        • Token Rotation
        • Federation
        • Audit Hooks
    """
    
    @staticmethod
    def issue_access_token(
        *,
        grant: Grant,
        device_public_key: bytes,
    ) -> str:
        
        GrantService.validate(grant)
        
        return issue_device_bound_token(
            user_id=str(grant.user_id),
            session_id=str(grant.session_id),
            jwt_id=str(grant.jwt_id),
            device_id=str(grant.device_id),
            device_public_key=device_public_key,
        )