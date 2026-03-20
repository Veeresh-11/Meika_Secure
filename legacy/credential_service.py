from sqlalchemy.orm import Session
from app.db.models import Credential
from app.security.password import hash_password, verify_password
from datetime import datetime


class CredentialService:

    @staticmethod
    def create_password_credential(
        db: Session,
        user_id,
        password: str
    ) -> Credential:
        password_hash = hash_password(password)

        credential = Credential(
            user_id=user_id,
            type="password",
            secret_ref=password_hash,
            status="active",
        )

        db.add(credential)
        db.commit()
        db.refresh(credential)
        return credential

    @staticmethod
    def verify_password_credential(
        db: Session,
        user_id,
        password: str
    ) -> bool:
        credential = (
            db.query(Credential)
            .filter(
                Credential.user_id == user_id,
                Credential.type == "password",
                Credential.status == "active",
            )
            .first()
        )

        if not credential:
            return False

        if verify_password(credential.secret_ref, password):
            credential.last_used_at = datetime.utcnow()
            db.commit()
            return True

        return False
