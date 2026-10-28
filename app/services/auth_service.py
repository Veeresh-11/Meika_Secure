from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta, timezone
from uuid import UUID
from fastapi import HTTPException

from app.db.models import User, Session as UserSession, AuditLog
from app.services.credential_service import CredentialService


# Deprecated password endpoints are restricted to the explicit legacy tenant.
LEGACY_TENANT_ID = UUID("00000000-0000-4000-8000-000000000001")


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
                tenant_id=LEGACY_TENANT_ID,
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
                tenant_id=user.tenant_id,
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
        *,
        commit: bool = True,
    ) -> UserSession | None:
        user = (
            db.query(User)
            .filter(
                User.tenant_id == LEGACY_TENANT_ID,
                User.email == email,
                User.status == "active",
            )
            .first()
        )

        if not user:
            return None

        if not CredentialService.verify_password_credential(
            db=db,
            user_id=user.id,
            password=password,
            commit=commit,
        ):
            return None

        session = UserSession(
            user_id=user.id,
            tenant_id=user.tenant_id,
            issued_at=datetime.now(timezone.utc).replace(tzinfo=None),
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1),
            revoked=False,
        )

        db.add(session)

        AuthService._audit(
            db,
            actor_type="user",
            actor_id=user.id,
            tenant_id=user.tenant_id,
            action="login",
            resource="session",
        )

        if commit:
            db.commit()
        else:
            db.flush()
        db.refresh(session)
        return session

    @staticmethod
    def _audit(
        db: Session,
        actor_type: str,
        actor_id,
        tenant_id,
        action: str,
        resource: str,
    ):
        audit = AuditLog(
            tenant_id=tenant_id,
            actor_type=actor_type,
            actor_id=actor_id,
            action=action,
            resource=resource,
        )
        db.add(audit)
        
    @staticmethod
    def get_user_by_email(
      db: Session,
      email: str,
      
    ) -> User | None:

      return (
         db.query(User)
         .filter(
             User.email == email,
             User.status == "active",
         )
         .first()
    )

    @staticmethod
    def get_user(
        db: Session,
        user_id: int,
    ) -> User | None:

     return (
        db.query(User)
        .filter(
            User.id == user_id,
        )
        .first()
    )

