from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session as DBSession

from app.db.models import Session, User
from app.db.device_models import Device


class SessionService:
    """
    Authentication Session lifecycle.

    A Session represents an authenticated login.

    Authorization Grants reference Sessions.
    """

    DEFAULT_EXPIRY = timedelta(hours=1)

    @staticmethod
    def create(
        db: DBSession,
        *,
        user_id,
        device_id,
        expires_at=None,
    ) -> Session:

        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise ValueError("Cannot create a session for an unknown user")

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
        if device is None:
            raise ValueError("Cannot create a session for a device outside the user's active tenant")

        now = datetime.now(timezone.utc).replace(tzinfo=None)

        session = Session(
            user_id=user_id,
            tenant_id=user.tenant_id,
            device_id=device_id,
            issued_at=now,
            expires_at=expires_at
            or now + SessionService.DEFAULT_EXPIRY,
            revoked=False,
            last_seen=now,
        )

        db.add(session)
        db.commit()
        db.refresh(session)

        return session

    @staticmethod
    def get(
        db: DBSession,
        *,
        session_id,
        tenant_id,
    ) -> Session | None:
        if tenant_id is None:
            raise ValueError("Tenant context is required to fetch a session")
        return (
            db.query(Session)
            .filter(
                Session.id == session_id,
                Session.tenant_id == tenant_id,
                Session.revoked.is_(False),
            )
            .first()
        )

    @staticmethod
    def validate(
        session: Session,
    ) -> None:

        if session is None:
            raise ValueError("Session not found")

        if session.revoked:
            raise ValueError("Session revoked")

        if session.expires_at <= datetime.now(timezone.utc).replace(tzinfo=None):
            raise ValueError("Session expired")

    @staticmethod
    def touch(
        db: DBSession,
        *,
        session: Session,
        tenant_id,
    ) -> Session:
        SessionService._require_tenant(session, tenant_id)
        session.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)

        db.commit()
        db.refresh(session)

        return session

    @staticmethod
    def revoke(
        db: DBSession,
        *,
        session: Session,
        tenant_id,
    ) -> Session:
        SessionService._require_tenant(session, tenant_id)
        session.revoked = True

        db.commit()
        db.refresh(session)

        return session

    @staticmethod
    def revoke_all_user_sessions(
        db: DBSession,
        *,
        user_id,
        tenant_id,
    ) -> int:
        if tenant_id is None:
            raise ValueError("Tenant context is required to revoke sessions")

        sessions = (
            db.query(Session)
            .filter(
                Session.user_id == user_id,
                Session.tenant_id == tenant_id,
                Session.revoked.is_(False),
            )
            .all()
        )

        for session in sessions:
            session.revoked = True

        db.commit()

        return len(sessions)

    @staticmethod
    def _require_tenant(session: Session, tenant_id) -> None:
        if tenant_id is None or getattr(session, "tenant_id", None) != tenant_id:
            raise ValueError("Session tenant mismatch")

    @staticmethod
    def cleanup(
        db: DBSession,
    ) -> int:

        expired = (
            db.query(Session)
            .filter(
                Session.expires_at < datetime.now(timezone.utc).replace(tzinfo=None),
                Session.revoked.is_(False),
            )
            .all()
        )

        for session in expired:
            session.revoked = True

        db.commit()

        return len(expired)