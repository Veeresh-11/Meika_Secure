from sqlalchemy.orm import Session
from app.db.models import Credential
from app.security.password import hash_password, verify_password
from datetime import datetime
from app.db.webauthn_models import WebAuthnCredential

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
    def create_webauthn_credential(
        db: Session,
         *,
        user_id,
        credential_id: str,
        device_id,
        public_key: str,
        hardware_backed: bool,
        attestation_verified: bool,
        attestation_type: str,
    ) -> WebAuthnCredential:

        credential = WebAuthnCredential(
        user_id=user_id,
        credential_id=credential_id,
        device_id=device_id,
        public_key=public_key,
        hardware_backed=hardware_backed,
        attestation_verified=attestation_verified,
        attestation_type=attestation_type,
    )

        db.add(credential)
        db.commit()
        db.refresh(credential)

        return credential
    
    @staticmethod
    def get_webauthn_credential(
      db: Session,
      credential_id: str,
    ) -> WebAuthnCredential | None:

     return (
        db.query(WebAuthnCredential)
        .filter(
            WebAuthnCredential.credential_id == credential_id,
            WebAuthnCredential.revoked.is_(False),
        )
        .first()
       )

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

    @staticmethod
    def update_sign_count(
        db: Session,
        credential: WebAuthnCredential,
        sign_count: int,
  ) -> WebAuthnCredential:

        credential.sign_count = sign_count

        db.commit()
        db.refresh(credential)

        return credential

    @staticmethod
    def touch_last_used(
        db: Session,
        credential: WebAuthnCredential,
    ) -> WebAuthnCredential:

        credential.last_used_at = datetime.utcnow()

        db.commit()
        db.refresh(credential)

        return credential

    @staticmethod
    def revoke_webauthn_credential(
        db: Session,
        credential: WebAuthnCredential,
    ) -> WebAuthnCredential:

        credential.revoked = True

        db.commit()
        db.refresh(credential)

        return credential
    
    @staticmethod
    def get_credentials_for_device(
      db: Session,
      *,
      device_id,
    ):

     return (
        db.query(WebAuthnCredential)
        .filter(
            WebAuthnCredential.device_id == device_id,
            WebAuthnCredential.revoked.is_(False),
        )
        .all()
    )
    
    @staticmethod
    def revoke_all_device_credentials(
        db: Session,
        *,
        device_id,
    ):
        credentials = (
            db.query(WebAuthnCredential)
            .filter(
                WebAuthnCredential.device_id == device_id,
                WebAuthnCredential.revoked.is_(False),
            )
            .all()
        )

        for credential in credentials:
            credential.revoked = True

        db.commit()

        return len(credentials)