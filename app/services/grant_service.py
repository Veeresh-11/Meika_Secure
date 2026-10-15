from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy.orm import Session

from app.db.grant_models import Grant
from app.db.models import User, Session as UserSession
from app.db.device_models import Device
from app.db.webauthn_models import WebAuthnCredential


class GrantService:
    """
    Authorization Grant lifecycle.

    A Grant is the server-side representation of an authenticated
    authorization. JWTs are signed representations of Grants.

    Future integrations:
        • Session Guardian
        • Meika Intelligence System (MIS)
        • Federation
        • Continuous Risk Evaluation
    """

    DEFAULT_EXPIRY = timedelta(hours=1)

    # ---------------------------------------------------------
    # Create
    # ---------------------------------------------------------

    @staticmethod
    def create(
        db: Session,
        *,
        user_id,
        session_id,
        credential_id,
        jwt_id: UUID,
        device_id,
        grant_type: str = "access",
        created_by: str = "webauthn",
    ) -> Grant:

        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise ValueError("Cannot create a grant for an unknown user")

        session = (
            db.query(UserSession)
            .filter(
                UserSession.id == session_id,
                UserSession.user_id == user_id,
                UserSession.tenant_id == user.tenant_id,
                UserSession.revoked.is_(False),
            )
            .first()
        )
        credential = (
            db.query(WebAuthnCredential)
            .filter(
                WebAuthnCredential.id == credential_id,
                WebAuthnCredential.user_id == user_id,
                WebAuthnCredential.tenant_id == user.tenant_id,
                WebAuthnCredential.revoked.is_(False),
            )
            .first()
        )
        device = (
            db.query(Device)
            .filter(
                Device.id == device_id,
                Device.user_id == user_id,
                Device.tenant_id == user.tenant_id,
                Device.state == "ACTIVE",
            )
            .first()
        )
        if session is None or credential is None or device is None:
            raise ValueError("Cannot create a grant with cross-tenant or inactive resources")
        if session.device_id != device.id or credential.device_id != device.id:
            raise ValueError("Grant session, credential, and device must belong to the same device")

        now = datetime.now(timezone.utc).replace(tzinfo=None)

        grant = Grant(
            user_id=user_id,
            tenant_id=user.tenant_id,
            session_id=session_id,
            credential_id=credential_id,
            jwt_id=jwt_id,
            device_id=device_id,
            grant_type=grant_type,
            created_by=created_by,
            issued_at=now,
            created_at=now,
            expires_at=now + GrantService.DEFAULT_EXPIRY,
            revoked=False,
        )

        db.add(grant)
        db.commit()
        db.refresh(grant)

        return grant

    # ---------------------------------------------------------
    # Read
    # ---------------------------------------------------------

    @staticmethod
    def get(
        db: Session,
        *,
        grant_id,
        tenant_id,
    ) -> Grant | None:
        if tenant_id is None:
            raise ValueError("Tenant context is required to fetch a grant")
        return (
            db.query(Grant)
            .filter(
                Grant.id == grant_id,
                Grant.tenant_id == tenant_id,
                Grant.revoked.is_(False),
            )
            .first()
        )

    @staticmethod
    def get_by_session(
        db: Session,
        *,
        session_id,
        tenant_id,
    ) -> list[Grant]:
        if tenant_id is None:
            raise ValueError("Tenant context is required to fetch grants by session")
        return (
            db.query(Grant)
            .filter(
                Grant.session_id == session_id,
                Grant.tenant_id == tenant_id,
                Grant.revoked.is_(False),
            )
            .all()
        )

    @staticmethod
    def get_by_jwt_id(
        db: Session,
        *,
        jwt_id,
        tenant_id,
    ) -> Grant | None:
        if tenant_id is None:
            raise ValueError("Tenant context is required to fetch a grant by JWT ID")
        return (
            db.query(Grant)
            .filter(
                Grant.jwt_id == jwt_id,
                Grant.tenant_id == tenant_id,
                Grant.revoked.is_(False),
            )
            .first()
        )

    # ---------------------------------------------------------
    # Validation
    # ---------------------------------------------------------

    @staticmethod
    def validate(
        grant: Grant,
    ) -> None:

        if grant is None:
            raise ValueError("Grant not found")

        if grant.revoked:
            raise ValueError("Grant revoked")

        if grant.expires_at <= datetime.now(timezone.utc).replace(tzinfo=None):
            raise ValueError("Grant expired")

        #
        # Session Guardian integration
        #

        if grant.guardian_state == "TERMINATED":
            raise ValueError("Session terminated")

        if grant.guardian_state == "CONTAINMENT":
            raise ValueError("Session contained")

        if grant.risk_level == "CRITICAL":
            raise ValueError("Grant blocked due to critical risk")

    # ---------------------------------------------------------
    # Runtime Updates
    # ---------------------------------------------------------

    @staticmethod
    def touch(
        db: Session,
        *,
        grant: Grant,
        tenant_id,
        ip_address: str | None = None,
    ) -> Grant:
        GrantService._require_tenant(grant, tenant_id)
        grant.last_used_at = datetime.now(timezone.utc).replace(tzinfo=None)

        if ip_address is not None:
            grant.last_used_ip = ip_address

        db.commit()
        db.refresh(grant)

        return grant

    @staticmethod
    def refresh(
        db: Session,
        *,
        grant: Grant,
        tenant_id,
    ) -> Grant:
        GrantService._require_tenant(grant, tenant_id)
        GrantService.validate(grant)

        now = datetime.now(timezone.utc).replace(tzinfo=None)

        grant.issued_at = now
        grant.expires_at = now + GrantService.DEFAULT_EXPIRY

        db.commit()
        db.refresh(grant)

        return grant

    @staticmethod
    def elevate_risk(
        db: Session,
        *,
        grant: Grant,
        tenant_id,
        risk_level: str,
    ) -> Grant:
        GrantService._require_tenant(grant, tenant_id)
        grant.risk_level = risk_level

        db.commit()
        db.refresh(grant)

        return grant

    @staticmethod
    def update_guardian_state(
        db: Session,
        *,
        grant: Grant,
        tenant_id,
        state: str,
    ) -> Grant:
        GrantService._require_tenant(grant, tenant_id)
        grant.guardian_state = state

        db.commit()
        db.refresh(grant)

        return grant

    # ---------------------------------------------------------
    # Revocation
    # ---------------------------------------------------------

    @staticmethod
    def revoke(
        db: Session,
        *,
        grant: Grant,
        tenant_id,
        reason: str | None = None,
    ) -> Grant:
        GrantService._require_tenant(grant, tenant_id)
        grant.revoked = True
        grant.revoked_at = datetime.now(timezone.utc).replace(tzinfo=None)
        grant.revocation_reason = reason

        db.commit()
        db.refresh(grant)

        return grant

    @staticmethod
    def revoke_all_for_user(
        db: Session,
        *,
        user_id,
        tenant_id,
        reason: str = "Bulk revocation",
    ) -> int:
        if tenant_id is None:
            raise ValueError("Tenant context is required to revoke grants")

        grants = (
            db.query(Grant)
            .filter(
                Grant.user_id == user_id,
                Grant.tenant_id == tenant_id,
                Grant.revoked.is_(False),
            )
            .all()
        )

        now = datetime.now(timezone.utc).replace(tzinfo=None)

        for grant in grants:
            grant.revoked = True
            grant.revoked_at = now
            grant.revocation_reason = reason

        db.commit()

        return len(grants)

    @staticmethod
    def revoke_by_session(
        db: Session,
        *,
        session_id,
        tenant_id,
        reason: str = "Session terminated",
    ) -> int:
        if tenant_id is None:
            raise ValueError("Tenant context is required to revoke grants by session")

        grants = (
            db.query(Grant)
            .filter(
                Grant.session_id == session_id,
                Grant.tenant_id == tenant_id,
                Grant.revoked.is_(False),
            )
            .all()
        )

        now = datetime.now(timezone.utc).replace(tzinfo=None)

        for grant in grants:
            grant.revoked = True
            grant.revoked_at = now
            grant.revocation_reason = reason

        db.commit()

        return len(grants)

    @staticmethod
    def _require_tenant(grant: Grant, tenant_id) -> None:
        if tenant_id is None or getattr(grant, "tenant_id", None) != tenant_id:
            raise ValueError("Grant tenant mismatch")

    # ---------------------------------------------------------
    # Maintenance
    # ---------------------------------------------------------

    @staticmethod
    def cleanup_expired(
        db: Session,
    ) -> int:

        expired = (
            db.query(Grant)
            .filter(
                Grant.expires_at < datetime.now(timezone.utc).replace(tzinfo=None),
                Grant.revoked.is_(False),
            )
            .all()
        )

        now = datetime.now(timezone.utc).replace(tzinfo=None)

        for grant in expired:
            grant.revoked = True
            grant.revoked_at = now
            grant.revocation_reason = "Grant expired"

        db.commit()

        return len(expired)