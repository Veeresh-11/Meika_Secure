from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta
from fastapi import HTTPException

from app.db.models import User, Session as UserSession, AuditLog
from app.services.credential_service import CredentialService


class AuthService:

    @staticmethod
    def register_user(
        db: Session,
        email: str,
        password: str,
        display_name: str | None = None,
    ) -> User:
        try:
            user = User(
                email=email,
                display_name=display_name,
                status="active",
            )
            db.add(user)
            db.flush()  # 🔑 ensures user.id exists

            CredentialService.create_password_credential(
                db=db,
                user_id=user.id,
                password=password,
            )

            AuthService._audit(
                db,
                actor_type="user",
                actor_id=user.id,
                action="register",
                resource="user",
            )

            db.commit()
            db.refresh(user)
            return user

        except IntegrityError:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="User already exists",
            )

    @staticmethod
    def login_user(
        db: Session,
        email: str,
        password: str,
    ) -> UserSession | None:
        user = (
            db.query(User)
            .filter(User.email == email, User.status == "active")
            .first()
        )

        if not user:
            return None

        if not CredentialService.verify_password_credential(
            db=db,
            user_id=user.id,
            password=password,
        ):
            return None

        session = UserSession(
            user_id=user.id,
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
            revoked=False,
        )

        db.add(session)

        AuthService._audit(
            db,
            actor_type="user",
            actor_id=user.id,
            action="login",
            resource="session",
        )

        db.commit()
        db.refresh(session)
        return session

    @staticmethod
    def _audit(
        db: Session,
        actor_type: str,
        actor_id,
        action: str,
        resource: str,
    ):
        audit = AuditLog(
            actor_type=actor_type,
            actor_id=actor_id,
            action=action,
            resource=resource,
        )
        db.add(audit)

