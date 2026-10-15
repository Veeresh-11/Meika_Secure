"""Standards-based FIDO2/WebAuthn ceremonies.

These endpoints accept browser WebAuthn JSON, verify it cryptographically, and
never trust client-supplied hardware/attestation booleans.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.config.settings import settings
from app.db.models import User
from app.db.session import SessionLocal
from app.db.webauthn_models import WebAuthnChallenge, WebAuthnCredential
from app.security.webauthn.fido2 import (
    FIDO2VerificationError,
    generate_authentication_options_json,
    generate_registration_options_json,
    verify_authentication,
    verify_registration,
    verify_enrollment_token,
)
from app.services.auth_service import AuthService
from app.services.webauthn.challenge_service import ChallengeService
from app.services.credential_service import CredentialService
from app.services.device_service import DeviceService
from app.services.grant_service import GrantService
from app.services.session_service import SessionService
from app.services.token_service import TokenService

router = APIRouter(prefix="/fido2", tags=["FIDO2 / WebAuthn"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class RegistrationOptionsRequest(BaseModel):
    email: EmailStr
    device_name: str = Field(min_length=1, max_length=128)
    model_config = ConfigDict(extra="forbid")


class RegistrationVerifyRequest(BaseModel):
    email: EmailStr
    challenge: str = Field(min_length=20, max_length=128)
    credential: dict[str, Any]
    device_name: str = Field(default="WebAuthn device", min_length=1, max_length=128)
    model_config = ConfigDict(extra="forbid")


class AuthenticationOptionsRequest(BaseModel):
    email: EmailStr
    model_config = ConfigDict(extra="forbid")


class AuthenticationVerifyRequest(BaseModel):
    email: EmailStr
    challenge: str = Field(min_length=20, max_length=128)
    credential: dict[str, Any]
    model_config = ConfigDict(extra="forbid")


def _consume_challenge(db: Session, record: WebAuthnChallenge, *, purpose: str, user_id) -> None:
    """Atomically consume a challenge exactly once, scoped to its user and purpose."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    result = db.execute(
        update(WebAuthnChallenge)
        .where(
            WebAuthnChallenge.id == record.id,
            WebAuthnChallenge.user_id == user_id,
            WebAuthnChallenge.purpose == purpose,
            WebAuthnChallenge.used.is_(False),
            WebAuthnChallenge.expires_at > now,
        )
        .values(used=True)
    )
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=400, detail="Invalid or expired WebAuthn challenge")
    db.commit()


@router.post("/registration/options")
def registration_options(payload: RegistrationOptionsRequest, authorization: str | None = Header(default=None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Passkey enrollment authorization required")
    try:
        enrollment = verify_enrollment_token(authorization.removeprefix("Bearer ").strip())
    except FIDO2VerificationError as exc:
        raise HTTPException(status_code=401, detail="Passkey enrollment authorization required") from exc

    user = AuthService.get_user_by_email(db, payload.email)
    if user is None or str(user.id) != enrollment["sub"]:
        raise HTTPException(status_code=401, detail="Passkey enrollment authorization required")

    enrollment_purpose = "fido2-register:" + enrollment["jti"]
    existing_challenge = (
        db.query(WebAuthnChallenge)
        .filter(WebAuthnChallenge.purpose == enrollment_purpose)
        .first()
    )
    if existing_challenge is not None:
        raise HTTPException(status_code=401, detail="Passkey enrollment authorization already used")
    challenge = ChallengeService.create(
        db=db, user_id=user.id, purpose=enrollment_purpose
    )

    existing = (
        db.query(WebAuthnCredential)
        .filter(
            WebAuthnCredential.user_id == user.id,
            WebAuthnCredential.tenant_id == user.tenant_id,
            WebAuthnCredential.revoked.is_(False),
        )
        .all()
    )
    try:
        options = generate_registration_options_json(
            rp_id=settings.webauthn_rp_id,
            rp_name=settings.webauthn_rp_name,
            user_id=user.id.bytes,
            user_name=user.email,
            challenge=challenge.challenge,
            exclude_credential_ids=[item.credential_id for item in existing],
        )
    except FIDO2VerificationError as exc:
        raise HTTPException(status_code=500, detail="Unable to create registration options") from exc

    return {"challenge": challenge.challenge, "options": options, "device_name": payload.device_name}


@router.post("/registration/verify")
def registration_verify(payload: RegistrationVerifyRequest, authorization: str | None = Header(default=None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Passkey enrollment authorization required")
    try:
        enrollment = verify_enrollment_token(authorization.removeprefix("Bearer ").strip())
    except FIDO2VerificationError as exc:
        raise HTTPException(status_code=401, detail="Passkey enrollment authorization required") from exc

    user = AuthService.get_user_by_email(db, payload.email)
    if user is None or str(user.id) != enrollment["sub"]:
        raise HTTPException(status_code=401, detail="Passkey enrollment authorization required")

    challenge = (
        db.query(WebAuthnChallenge)
        .filter(WebAuthnChallenge.challenge == payload.challenge)
        .first()
    )
    if challenge is None or challenge.user_id != user.id or challenge.purpose != ("fido2-register:" + enrollment["jti"]):
        raise HTTPException(status_code=400, detail="Invalid registration ceremony")
    if challenge.used or challenge.expires_at <= datetime.now(timezone.utc).replace(tzinfo=None):
        raise HTTPException(status_code=400, detail="Invalid or expired WebAuthn challenge")

    try:
        verified = verify_registration(
            credential=payload.credential,
            challenge=challenge.challenge,
            expected_origin=settings.webauthn_origin_list,
            expected_rp_id=settings.webauthn_rp_id,
        )
    except FIDO2VerificationError as exc:
        raise HTTPException(status_code=422, detail="WebAuthn registration verification failed") from exc

    # Do not label credentials as hardware-backed merely because registration
    # succeeded. Platform and synced passkeys are valid WebAuthn credentials.
    _consume_challenge(db, challenge, purpose="fido2-register", user_id=user.id)

    device = DeviceService.register(
        db=db,
        user_id=user.id,
        device_identifier=verified["credential_id"],
        device_name=payload.device_name,
        hardware_backed=False,
        attestation_verified=True,
    )
    CredentialService.create_webauthn_credential(
        db=db,
        user_id=user.id,
        device_id=device.id,
        credential_id=verified["credential_id"],
        public_key=verified["public_key"],
        hardware_backed=False,
        attestation_verified=True,
        attestation_type=verified["attestation_type"],
    )
    credential_record = (
        db.query(WebAuthnCredential)
        .filter(
            WebAuthnCredential.user_id == user.id,
            WebAuthnCredential.tenant_id == user.tenant_id,
            WebAuthnCredential.credential_id == verified["credential_id"],
        )
        .first()
    )
    if credential_record is not None and credential_record.sign_count != verified["sign_count"]:
        credential_record.sign_count = verified["sign_count"]
        db.commit()

    return {"status": "registered", "credential_id": verified["credential_id"]}


@router.post("/authentication/options")
def authentication_options(payload: AuthenticationOptionsRequest, db: Session = Depends(get_db)):
    user = AuthService.get_user_by_email(db, payload.email)
    if user is None:
        # Avoid disclosing whether an account exists.
        raise HTTPException(status_code=401, detail="Authentication failed")

    credentials = (
        db.query(WebAuthnCredential)
        .filter(
            WebAuthnCredential.user_id == user.id,
            WebAuthnCredential.tenant_id == user.tenant_id,
            WebAuthnCredential.revoked.is_(False),
        )
        .all()
    )
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication failed")

    challenge = ChallengeService.create(db=db, user_id=user.id, purpose="fido2-authenticate")
    try:
        options = generate_authentication_options_json(
            rp_id=settings.webauthn_rp_id,
            challenge=challenge.challenge,
            credential_ids=[item.credential_id for item in credentials],
        )
    except FIDO2VerificationError as exc:
        raise HTTPException(status_code=500, detail="Unable to create authentication options") from exc
    return {"challenge": challenge.challenge, "options": options}


@router.post("/authentication/verify")
def authentication_verify(payload: AuthenticationVerifyRequest, db: Session = Depends(get_db)):
    user = AuthService.get_user_by_email(db, payload.email)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed")

    challenge = (
        db.query(WebAuthnChallenge)
        .filter(WebAuthnChallenge.challenge == payload.challenge)
        .first()
    )
    if (
        challenge is None
        or challenge.user_id != user.id
        or challenge.purpose != "fido2-authenticate"
        or challenge.used
        or challenge.expires_at <= datetime.now(timezone.utc).replace(tzinfo=None)
    ):
        raise HTTPException(status_code=401, detail="Authentication failed")

    credential_id = payload.credential.get("id")
    if not isinstance(credential_id, str) or not credential_id:
        raise HTTPException(status_code=401, detail="Authentication failed")
    record = CredentialService.get_webauthn_credential(
        db=db,
        credential_id=credential_id,
        user_id=user.id,
        tenant_id=user.tenant_id,
    )
    if record is None:
        raise HTTPException(status_code=401, detail="Authentication failed")

    try:
        verified = verify_authentication(
            credential=payload.credential,
            challenge=challenge.challenge,
            expected_origin=settings.webauthn_origin_list,
            expected_rp_id=settings.webauthn_rp_id,
            credential_public_key=record.public_key,
            current_sign_count=record.sign_count,
        )
    except FIDO2VerificationError as exc:
        raise HTTPException(status_code=401, detail="Authentication failed") from exc

    from webauthn.helpers import base64url_to_bytes
    if verified["credential_id"] != base64url_to_bytes(record.credential_id):
        raise HTTPException(status_code=401, detail="Authentication failed")

    _consume_challenge(db, challenge, purpose="fido2-authenticate", user_id=user.id)
    CredentialService.update_sign_count(db=db, credential=record, sign_count=verified["new_sign_count"])
    CredentialService.touch_last_used(db=db, credential=record)

    session = SessionService.create(db=db, user_id=user.id, device_id=record.device_id)
    grant = GrantService.create(
        db=db,
        user_id=user.id,
        session_id=session.id,
        credential_id=record.id,
        jwt_id=uuid4(),
        device_id=record.device_id,
        grant_type="access",
        created_by="fido2-webauthn",
    )
    device = DeviceService.get(db=db, device_id=record.device_id)
    if device is not None:
        DeviceService.touch(db=db, device=device)
    GrantService.touch(db=db, grant=grant)
    from webauthn.helpers import base64url_to_bytes
    token = TokenService.issue_access_token(
        grant=grant,
        device_public_key=record.public_key.encode(),
    )
    return {
        "status": "authenticated",
        "grant_id": str(grant.id),
        "session_id": str(session.id),
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3600,
    }
