from sqlalchemy.orm import Session
from app.db.models import Credential, User
from app.security.password import hash_password, verify_password
from datetime import datetime, timezone
from app.db.webauthn_models import WebAuthnCredential
from app.db.device_models import Device

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

        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise ValueError("Cannot create a WebAuthn credential for an unknown user")

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
            raise ValueError("Cannot create a WebAuthn credential for a device outside the user's active tenant")

        credential = WebAuthnCredential(
        user_id=user_id,
        tenant_id=user.tenant_id,
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
        *,
        credential_id: str,
        user_id,
        tenant_id,
    ) -> WebAuthnCredential | None:
        """Fetch an active credential only within its owning user and tenant."""
        return (
            db.query(WebAuthnCredential)
            .filter(
                WebAuthnCredential.credential_id == credential_id,
                WebAuthnCredential.user_id == user_id,
                WebAuthnCredential.tenant_id == tenant_id,
                WebAuthnCredential.revoked.is_(False),
            )
            .first()
        )

    @staticmethod
    def verify_password_credential(
        db: Session,
        user_id,
        password: str,
        *,
        tenant_id,
    ) -> bool:
        if tenant_id is None:
            raise ValueError("Tenant context is required to verify a password credential")
        credential = (
            db.query(Credential)
            .join(User, Credential.user_id == User.id)
            .filter(
                Credential.user_id == user_id,
                User.tenant_id == tenant_id,
                Credential.type == "password",
                Credential.status == "active",
            )
            .first()
        )

        if not credential:
            return False

        if verify_password(credential.secret_ref, password):
            credential.last_used_at = datetime.now(timezone.utc).replace(tzinfo=None)
            db.commit()
            return True

        return False

    @staticmethod
    def update_sign_count(
        db: Session,
        credential: WebAuthnCredential,
        sign_count: int,
        *,
        tenant_id,
    ) -> WebAuthnCredential:
        CredentialService._require_tenant(credential, tenant_id)
        credential.sign_count = sign_count

        db.commit()
        db.refresh(credential)

        return credential

    @staticmethod
    def touch_last_used(
        db: Session,
        credential: WebAuthnCredential,
        *,
        tenant_id,
    ) -> WebAuthnCredential:
        CredentialService._require_tenant(credential, tenant_id)
        credential.last_used_at = datetime.now(timezone.utc).replace(tzinfo=None)

        db.commit()
        db.refresh(credential)

        return credential

    @staticmethod
    def revoke_webauthn_credential(
        db: Session,
        credential: WebAuthnCredential,
        *,
        tenant_id,
    ) -> WebAuthnCredential:
        CredentialService._require_tenant(credential, tenant_id)
        credential.revoked = True

        db.commit()
        db.refresh(credential)

        return credential
    
    @staticmethod
    def _require_tenant(credential: WebAuthnCredential, tenant_id) -> None:
        if tenant_id is None or getattr(credential, "tenant_id", None) != tenant_id:
            raise ValueError("WebAuthn credential tenant mismatch")

    @staticmethod
    def get_credentials_for_device(
      db: Session,
      *,
      device_id,
      tenant_id,
    ):
     if tenant_id is None:
         raise ValueError("Tenant context is required to fetch device credentials")
     return (
        db.query(WebAuthnCredential)
        .filter(
            WebAuthnCredential.device_id == device_id,
            WebAuthnCredential.tenant_id == tenant_id,
            WebAuthnCredential.revoked.is_(False),
        )
        .all()
    )
    
    @staticmethod
    def revoke_all_device_credentials(
        db: Session,
        *,
        device_id,
        tenant_id,
    ):
        if tenant_id is None:
            raise ValueError("Tenant context is required to revoke device credentials")
        credentials = (
            db.query(WebAuthnCredential)
            .filter(
                WebAuthnCredential.device_id == device_id,
                WebAuthnCredential.tenant_id == tenant_id,
                WebAuthnCredential.revoked.is_(False),
            )
            .all()
        )

        for credential in credentials:
            credential.revoked = True

        db.commit()

        return len(credentials)