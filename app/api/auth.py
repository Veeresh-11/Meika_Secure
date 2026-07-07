from fastapi import APIRouter, Depends, HTTPException, Request, Body
from sqlalchemy.orm import Session
from pydantic import ( BaseModel, Field, EmailStr, ConfigDict, )
import logging
from datetime import datetime
from app.security.persistence import db
from app.security.webauthn.attestation import (
    AttestationVerificationError,verify_attestation)
from app.db.session import SessionLocal
from app.services.auth_service import AuthService
from typing import Literal

from app.security.bootstrap import build_pipeline
from app.security.context import SecurityContext
from app.security.device.context import DeviceContext
from app.security.device.registry import DeviceRegistry
from app.security.device.posture import DevicePostureEvaluator
from app.security.errors import SecurityPipelineError
from app.security.device.context import (
    DeviceIdentityContext,
    DevicePostureContext,
)
from app.security.device_snapshot import DeviceSnapshot
from app.security.webauthn.assertion import verify_assertion
from app.security.webauthn.models import WebAuthnCredential
from app.services.webauthn.challenge_service import ChallengeService
from app.services.credential_service import CredentialService
from app.services.grant_service import GrantService
from uuid import uuid4
from app.services.session_service import SessionService
from app.services.token_service import TokenService
from app.services.device_service import DeviceService

# Set up structured logger for deprecation tracking
logger = logging.getLogger("meika.auth.deprecation")

router = APIRouter(prefix="/auth")

pipeline = build_pipeline()
device_registry = DeviceRegistry()
posture_evaluator = DevicePostureEvaluator()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --------------------
# Models
# --------------------
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=10)
    display_name: str | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=10)
    device_id: str = Field(..., min_length=3)
    device_signals: dict = Field(default_factory=dict)


class WebAuthnRegisterStartRequest(BaseModel):
    email: EmailStr
    device_name: str = Field(
        ...,
        min_length=1,
        description="Human-readable device name"
    )

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------
# WebAuthn Attestation Models
# ---------------------------------------------------------

class AttestationResponse(BaseModel):
    response: dict = Field(
        ...,
        description="Authenticator attestation response"
    )

    model_config = ConfigDict(extra="allow")


class AttestationPayload(BaseModel):
    challenge: str = Field(..., min_length=1)

    hardware_backed: Literal[True]

    attestation_verified: Literal[True]

    public_key: str = Field(..., min_length=1)

    type: str = Field(
        default="unknown",
        min_length=1,
    )
    credential_id: str | None = None

    model_config = ConfigDict(
        extra="forbid"
    )


class WebAuthnRegisterFinishRequest(BaseModel):
    email: EmailStr
    attestation: AttestationPayload

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------
# WebAuthn Authentication Models
# ---------------------------------------------------------

class WebAuthnAuthenticateStartRequest(BaseModel):
    email: EmailStr

    model_config = ConfigDict(extra="forbid")


class AssertionResponse(BaseModel):
    response: dict = Field(
        ...,
        description="Authenticator assertion response"
    )

    model_config = ConfigDict(extra="allow")


class AssertionPayload(BaseModel):
    id: str = Field(..., min_length=1)
    rawId: str = Field(..., min_length=1)
    type: str = Field(..., min_length=1)

    response: AssertionResponse

    model_config = ConfigDict(extra="allow")


class WebAuthnAuthenticateFinishRequest(BaseModel):
    email: EmailStr

    credential_id: str = Field(
        ...,
        min_length=1,
    )

    assertion: AssertionPayload

    model_config = ConfigDict(extra="forbid")
# --------------------
# Register (DEPRECATED - Password)
# --------------------

@router.post(
    "/register",
    deprecated=True,
    tags=["Deprecated"],
    responses={
        200: {"description": "Success"},
        400: {"description": "Malformed request body"},
        409: {"description": "User already exists"},
        422: {"description": "Validation Error"},
    },
)
def register(payload: RegisterRequest = Body(...), db: Session = Depends(get_db)):
    """
    DEPRECATED: Use POST /auth/webauthn/register/start instead.
    
    Password registration is provided for backward compatibility only.
    All future authentication must use WebAuthn / passwordless.
    """
    
    logger.warning(
        "Password registration used",
        extra={
            "email": payload.email,
            "event": "password_registration_deprecated",
            "severity": "WARNING",
            "timestamp": datetime.utcnow().isoformat(),
        }
    )

    try:
        user = AuthService.register_user(
            db=db,
            email=payload.email,
            password=payload.password,
            display_name=payload.display_name,
        )
    except Exception:
        raise HTTPException(status_code=409, detail="User already exists")
    
    
    return {
        "user_id": str(user.id),
        "warning": "Password authentication is deprecated. Please use WebAuthn instead.",
    }


# --------------------
# Login (DEPRECATED - Password)
# --------------------

@router.post(
    "/login",
    deprecated=True,
    tags=["Deprecated"],
    responses={
        200: {"description": "Success"},
        400: {"description": "Malformed request body"},
        401: {"description": "Invalid credentials"},
        403: {"description": "Access denied"},
        422: {"description": "Validation Error"},
    },
)
def login(
    payload: LoginRequest = Body(...),
    request: Request = None,
    db: Session = Depends(get_db),
):
    """
    DEPRECATED: Use POST /auth/webauthn/authenticate/start instead.
    
    Password login is provided for backward compatibility only.
    All future authentication must use WebAuthn / passwordless.
    """
    
    logger.warning(
        "Password login used",
        extra={
            "email": payload.email,
            "device_id": payload.device_id,
            "event": "password_login_deprecated",
            "severity": "WARNING",
            "timestamp": datetime.utcnow().isoformat(),
        }
    )

    # ---- Step 1: Authenticate ----
    try:
        session = AuthService.login_user(
            db=db,
            email=payload.email,
            password=payload.password,
        )
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not session:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    principal_id = str(session.user_id)

   # ---- Step 2: Device Context ----
    try:

      posture = posture_evaluator.evaluate(payload.device_signals)

      if isinstance(posture, DevicePostureContext):
         posture_ctx = posture
      else:
        posture_ctx = DevicePostureContext(
            secure_boot=bool(posture.get("secure_boot", True)),
            compromised=bool(posture.get("compromised", False)),
        )

      device_ctx = DeviceContext(
        device_id=payload.device_id,
        registered=device_registry.is_registered(
            payload.device_id,
            principal_id,
        ),
        state="active",
        identity=DeviceIdentityContext(
            hardware_backed=True,
            attestation_verified=True,
            binding_valid=True,
            clone_confirmed=False,
            replay_detected=False,
            last_attested_at=datetime.utcnow(),
        ),
        posture=posture_ctx,
    )

    except Exception:
      raise HTTPException(
        status_code=400,
        detail="Invalid device context",
    )
    
    # ---- Step 3: Security Context ----
    

    device_snapshot = DeviceSnapshot(
    device_id=device_ctx.device_id,
    registered=device_ctx.registered,
    state=device_ctx.state,

    hardware_backed=device_ctx.identity.hardware_backed,
    attestation_verified=device_ctx.identity.attestation_verified,
    binding_valid=device_ctx.identity.binding_valid,

    secure_boot=device_ctx.posture.secure_boot,

    replay_detected=device_ctx.identity.replay_detected,
    compromised=device_ctx.posture.compromised,
    clone_confirmed=device_ctx.identity.clone_confirmed,
    )

    security_ctx = SecurityContext(
     request_id="login-request",
     principal_id=principal_id,
     authenticated=True,
     intent="user.login",
     device_id=device_snapshot.device_id,
     device=device_snapshot,
     risk_signals={},
     request_time=datetime.utcnow(),
     metadata={},
    )
    # ---- Step 4: Zero Trust ----
    try:
      decision = pipeline.evaluate(security_ctx)

    except Exception as exc:
      import traceback
      traceback.print_exc()

      if isinstance(exc, SecurityPipelineError):
        raise HTTPException(
            status_code=403,
            detail="Access denied",
        )

      raise HTTPException(
        status_code=403,
        detail="Security evaluation failed",
      )

    return {
        "session_id": str(session.id),
        "expires_at": session.expires_at,
        "decision": decision.outcome.value,
        "warning": "Password authentication is deprecated. Please use WebAuthn instead.",
    }


# --------------------
# WebAuthn: Register Start
# --------------------

@router.post(
    "/webauthn/register/start",
    tags=["WebAuthn"],
    responses={
        200: {"description": "Registration session created"},
        400: {"description": "Malformed request"},
        409: {"description": "User already exists"},
    },
)
def webauthn_register_start(
    payload: WebAuthnRegisterStartRequest = Body(...),
    db: Session = Depends(get_db),
):
    """
    Initiate WebAuthn credential registration.
    
    Returns challenge and registration options for client-side WebAuthn call.
    
    Client should:
    1. Call navigator.credentials.create() with returned options
    2. POST attestation response to /auth/webauthn/register/finish
    """
    try:
        user = AuthService.get_user_by_email(
        db,
        payload.email,
       )

        if user is None:
         raise HTTPException(
         status_code=404,
         detail="User not found",
        )
        
        challenge_record = ChallengeService.create(
        db=db,
        user_id=user.id,      # or the resolved UUID for the user
        purpose="register",
        )

        challenge = challenge_record.challenge
        
        logger.info(
            "WebAuthn registration started",
            extra={
                "email": payload.email,
                "device_name": payload.device_name,
                "event": "webauthn_register_start",
            }
        )
        
        return {
            "challenge": challenge,
            "rp": {
                "id": "meika.example.com",
                "name": "Meika Authenticator"
            },
            "user": {
                "id": payload.email,  # Use email as user ID
                "name": payload.email,
                "displayName": payload.device_name,
            },
            "timeout": 60000,
            "attestation": "direct",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "userVerification": "required",
            },
            "pubKeyCredParams": [
                {"alg": -7, "type": "public-key"}  # ES256
            ]
        }
    except HTTPException:
        raise

    except Exception as e:
        logger.exception(
            "WebAuthn Registration start failed"
        )

        raise HTTPException(
            status_code=400,
            detail="Registration failed",
        )
# --------------------
# WebAuthn: Register Finish
# --------------------

@router.post(
    "/webauthn/register/finish",
    tags=["WebAuthn"],
    responses={
    200: {"description": "Credential registered"},
    400: {"description": "Malformed request body"},
    401: {"description": "User not found"},
    422: {"description": "Invalid attestation or validation error"},
    500: {"description": "Internal server error"},
},
)
def webauthn_register_finish(
    payload: WebAuthnRegisterFinishRequest = Body(...),
    db: Session = Depends(get_db),
):
    """
    Complete WebAuthn credential registration.
    
    Verifies attestation and stores credential for future authentication.
    """
    try:
        
        challenge = ChallengeService.get(
          db=db,
          challenge=payload.attestation.challenge,
        )

        ChallengeService.validate(challenge)

        credential_data = verify_attestation(
        payload.attestation.model_dump(),
        challenge.challenge,
        )

        ChallengeService.consume(
         db=db,
         challenge=challenge,
        )
        
        device = DeviceService.get_by_identifier(
        db=db,
        device_identifier=payload.attestation.credential_id,
        )

        if device is None:
          device = DeviceService.register(
            db=db,
            user_id=challenge.user_id,
            device_identifier=payload.attestation.credential_id,
            device_name= "WebAuthn Device",
            hardware_backed=payload.attestation.hardware_backed,
            attestation_verified=True,
            )
         
        credential = CredentialService.create_webauthn_credential(
         db=db,
         user_id=challenge.user_id,
         device_id=device.id,
         credential_id=credential_data["credential_id"],
         public_key=payload.attestation.public_key,
         hardware_backed=payload.attestation.hardware_backed,
         attestation_verified=payload.attestation.attestation_verified,
         attestation_type=payload.attestation.type,
     )
        
        
        logger.info(
            "WebAuthn credential registered",
            extra={
                "email": payload.email,
                "event": "webauthn_register_finish",
                "credential_id": credential_data.get("credential_id", "unknown"),
            }
        )
        
        return {
            "status": "registered",
            "credential_id": credential_data.get("credential_id"),
            "message": "WebAuthn credential successfully registered"
        }
    except AttestationVerificationError as e:
      logger.warning(
        f"WebAuthn attestation validation failed: {e}"
        )

      raise HTTPException(
        status_code=422,
        detail=str(e),
        )

    except Exception as e:
        logger.exception(
        "Unexpected WebAuthn registration error"
       )

        raise HTTPException(
        status_code=500,
        detail="Internal server error",
       )

# --------------------
# WebAuthn: Authenticate Start
# --------------------

@router.post(
    "/webauthn/authenticate/start",
    tags=["WebAuthn"],
    responses={
        200: {"description": "Authentication challenge generated"},
        400: {"description": "Malformed request body"},
        401: {"description": "User not found or no credentials"},
        422: {"description": "Validation error"},
    },
)
def webauthn_authenticate_start(
    payload: WebAuthnAuthenticateStartRequest = Body(...),
    db: Session = Depends(get_db),
):
    """
    Initiate WebAuthn authentication.
    
    Returns challenge and credential list for client-side WebAuthn call.
    
    Client should:
    1. Call navigator.credentials.get() with returned options
    2. POST assertion response to /auth/webauthn/authenticate/finish
    """
    try:
        
        user = AuthService.get_user_by_email(
        db,
        payload.email,
     )  

        if user is None:
         raise HTTPException(
         status_code=404,
         detail="User not found",
       )
        
        challenge_record = ChallengeService.create(
          db=db,
          user_id=user.id,
          purpose="authenticate",
        )

        challenge = challenge_record.challenge
        
        
        logger.info(
            "WebAuthn authentication started",
            extra={
                "email": payload.email,
                "event": "webauthn_auth_start",
            }
        )
        
        return {
            "challenge": challenge,
            "timeout": 60000,
            "rpId": "meika.example.com",
            "allowCredentials": [
               
            ]
        }
    except HTTPException :
        raise 
    
    except Exception as e:
        logger.exception(
            "WebAuthn authentication start failed"
        )

        raise HTTPException(
            status_code=400,
            detail="Authentication failed",
        )

# --------------------
# WebAuthn: Authenticate Finish
# --------------------

@router.post(
    "/webauthn/authenticate/finish",
    tags=["WebAuthn"],
    responses={
        200: {"description": "Authenticated successfully"},
        400: {"description": "Malformed request body"},
        401: {"description": "Invalid assertion or credential"},
        403: {"description": "Access denied by policy"},
        422: {"description": "Validation error"},
    },
)
def webauthn_authenticate_finish(
    payload: WebAuthnAuthenticateFinishRequest = Body(...),
    db: Session = Depends(get_db),
):
    """
    Complete WebAuthn authentication.

    Workflow:

        Verify Assertion
              ↓
        Update Credential
              ↓
        Create Session
              ↓
        Create Authorization Grant
              ↓
        Issue Device-Bound JWT
              ↓
        Return Authenticated Session
    """

    try:

        # --------------------------------------------------
        # Load credential
        # --------------------------------------------------

        credential_record = CredentialService.get_webauthn_credential(
            db=db,
            credential_id=payload.credential_id,
        )

        if credential_record is None:
            raise HTTPException(
                status_code=401,
                detail="Credential not found",
            )

        # --------------------------------------------------
        # Load user
        # --------------------------------------------------

        user = AuthService.get_user_by_email(
            db,
            payload.email,
        )

        if user is None:
            raise HTTPException(
                status_code=404,
                detail="User not found",
            )

        # --------------------------------------------------
        # Convert DB model into WebAuthn verification model
        # --------------------------------------------------

        credential = WebAuthnCredential(
            credential_id=credential_record.credential_id.encode(),
            public_key=credential_record.public_key.encode(),
            sign_count=credential_record.sign_count,
            hardware_backed=credential_record.hardware_backed,
            attestation_verified=credential_record.attestation_verified,
            attestation_type=credential_record.attestation_type,
            created_at=credential_record.created_at,
            last_used_at=credential_record.last_used_at,
            revoked=credential_record.revoked,
        )

        # --------------------------------------------------
        # Verify assertion
        # --------------------------------------------------

        verify_assertion(
            payload.assertion.model_dump(),
            credential,
        )

        # --------------------------------------------------
        # Update credential metadata
        # --------------------------------------------------

        CredentialService.update_sign_count(
            db=db,
            credential=credential_record,
            sign_count=credential.sign_count,
        )

        CredentialService.touch_last_used(
            db=db,
            credential=credential_record,
        )

        # --------------------------------------------------
        # Create authenticated session
        # --------------------------------------------------

        session = SessionService.create(
            db=db,
            user_id=user.id,
            device_id=credential_record.device_id,
        )

        # --------------------------------------------------
        # Create authorization grant
        # --------------------------------------------------
         
    # TODO(Device Persistence):
# credential_record.id currently acts as a temporary
# device identifier.
#
# Replace with Device.id after introducing the
# identity.devices table.
        grant = GrantService.create(
             db=db,
            user_id=user.id,
            session_id=session.id,
            credential_id=credential_record.id,
            jwt_id=uuid4(),
            device_id=credential_record.device_id,
            grant_type="access",
            created_by="webauthn",
        )

        # --------------------------------------------------
        # Update Device Activity
        # --------------------------------------------------

        device = DeviceService.get(
            db=db,
            device_id=credential_record.device_id,
        )

        if device:
            DeviceService.touch(
                 db=db,
                device=device,
        )

        # --------------------------------------------------
        # Update Grant Activity
        # --------------------------------------------------

        GrantService.touch(
            db=db,
            grant=grant,
        )
        

        # --------------------------------------------------
        # Issue JWT
        # --------------------------------------------------

        access_token = TokenService.issue_access_token(
            db=db,
            grant=grant,
            device_public_key=credential.public_key,
        )

        # --------------------------------------------------
        # Audit Log
        # --------------------------------------------------

        logger.info(
            "WebAuthn authentication successful",
            extra={
                "user_id": str(user.id),
                "email": payload.email,
                "credential_id": payload.credential_id,
                "grant_id": str(grant.id),
                "session_id": str(session.id),
                "jwt_id": str(grant.jwt_id),
                "event": "webauthn_auth_success",
            },
        )

        # --------------------------------------------------
        # Response
        # --------------------------------------------------

        return {
            "status": "authenticated",
            "grant_id": str(grant.id),
            "session_id": str(session.id),
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        }

    except HTTPException:
        raise

    except Exception:
        logger.exception(
            "WebAuthn authentication failed",
            extra ={
                "email": payload.email,
                "credential_id": payload.credential_id,
                "event": "webauthn_auth_failure",},
        )

        raise HTTPException(
            status_code=401,
            detail="Authentication failed",
        )