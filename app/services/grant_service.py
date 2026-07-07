from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy.orm import Session

from app.db.grant_models import Grant


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

        now = datetime.utcnow()

        grant = Grant(
            user_id=user_id,
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
    ) -> Grant | None:

        return (
            db.query(Grant)
            .filter(
                Grant.id == grant_id,
                Grant.revoked.is_(False),
            )
            .first()
        )

    @staticmethod
    def get_by_session(
        db: Session,
        *,
        session_id,
    ) -> list[Grant]:

        return (
            db.query(Grant)
            .filter(
                Grant.session_id == session_id,
                Grant.revoked.is_(False),
            )
            .all()
        )

    @staticmethod
    def get_by_jwt_id(
        db: Session,
        *,
        jwt_id,
    ) -> Grant | None:

        return (
            db.query(Grant)
            .filter(
                Grant.jwt_id == jwt_id,
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

        if grant.expires_at <= datetime.utcnow():
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
        ip_address: str | None = None,
    ) -> Grant:

        grant.last_used_at = datetime.utcnow()

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
    ) -> Grant:

        GrantService.validate(grant)

        now = datetime.utcnow()

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
        risk_level: str,
    ) -> Grant:

        grant.risk_level = risk_level

        db.commit()
        db.refresh(grant)

        return grant

    @staticmethod
    def update_guardian_state(
        db: Session,
        *,
        grant: Grant,
        state: str,
    ) -> Grant:

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
        reason: str | None = None,
    ) -> Grant:

        grant.revoked = True
        grant.revoked_at = datetime.utcnow()
        grant.revocation_reason = reason

        db.commit()
        db.refresh(grant)

        return grant

    @staticmethod
    def revoke_all_for_user(
        db: Session,
        *,
        user_id,
        reason: str = "Bulk revocation",
    ) -> int:

        grants = (
            db.query(Grant)
            .filter(
                Grant.user_id == user_id,
                Grant.revoked.is_(False),
            )
            .all()
        )

        now = datetime.utcnow()

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
        reason: str = "Session terminated",
    ) -> int:

        grants = (
            db.query(Grant)
            .filter(
                Grant.session_id == session_id,
                Grant.revoked.is_(False),
            )
            .all()
        )

        now = datetime.utcnow()

        for grant in grants:
            grant.revoked = True
            grant.revoked_at = now
            grant.revocation_reason = reason

        db.commit()

        return len(grants)

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
                Grant.expires_at < datetime.utcnow(),
                Grant.revoked.is_(False),
            )
            .all()
        )

        now = datetime.utcnow()

        for grant in expired:
            grant.revoked = True
            grant.revoked_at = now
            grant.revocation_reason = "Grant expired"

        db.commit()

        return len(expired)