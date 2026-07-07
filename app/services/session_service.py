from datetime import datetime, timedelta

from sqlalchemy.orm import Session as DBSession

from app.db.models import Session


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

        now = datetime.utcnow()

        session = Session(
            user_id=user_id,
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
    ) -> Session | None:

        return (
            db.query(Session)
            .filter(Session.id == session_id, Session.revoked.is_(False))
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

        if session.expires_at <= datetime.utcnow():
            raise ValueError("Session expired")

    @staticmethod
    def touch(
        db: DBSession,
        *,
        session: Session,
    ) -> Session:

        session.last_seen = datetime.utcnow()

        db.commit()
        db.refresh(session)

        return session

    @staticmethod
    def revoke(
        db: DBSession,
        *,
        session: Session,
    ) -> Session:

        session.revoked = True

        db.commit()
        db.refresh(session)

        return session

    @staticmethod
    def revoke_all_user_sessions(
        db: DBSession,
        *,
        user_id,
    ) -> int:

        sessions = (
            db.query(Session)
            .filter(
                Session.user_id == user_id,
                Session.revoked.is_(False),
            )
            .all()
        )

        for session in sessions:
            session.revoked = True

        db.commit()

        return len(sessions)

    @staticmethod
    def cleanup(
        db: DBSession,
    ) -> int:

        expired = (
            db.query(Session)
            .filter(
                Session.expires_at < datetime.utcnow(),
                Session.revoked.is_(False),
            )
            .all()
        )

        for session in expired:
            session.revoked = True

        db.commit()

        return len(expired)