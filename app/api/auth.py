from fastapi import APIRouter, Depends, HTTPException, Request, Body
from sqlalchemy.orm import Session
from pydantic import ( BaseModel, Field, EmailStr, ConfigDict, )
import logging
from datetime import datetime
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
from app.security.webauthn.models import WebAuthnCredential
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
        device_ctx = DeviceContext(
            device_id=payload.device_id,
            registered=device_registry.is_registered(payload.device_id, principal_id),
            posture=posture_evaluator.evaluate(payload.device_signals),
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid device context")

    # ---- Step 3: Security Context ----
    security_ctx = SecurityContext(
        principal_id=principal_id,
        authenticated=True,
        intent="user.login",
        device=device_ctx,
    )

    # ---- Step 4: Zero Trust ----
    try:
        decision = pipeline.evaluate(security_ctx)
    except SecurityPipelineError:
        raise HTTPException(status_code=403, detail="Access denied")
    except Exception:
        raise HTTPException(status_code=403, detail="Security evaluation failed")

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
        from app.security.webauthn.challenge import generate_challenge
        
        challenge = generate_challenge()
        
        # TODO: Store registration session in DB with TTL
        # For now, return challenge
        
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
    except Exception as e:
        logger.error(f"WebAuthn registration start failed: {e}")
        raise HTTPException(status_code=400, detail="Registration failed")


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
        from app.security.webauthn.attestation import verify_attestation
        
        # Verify attestation (would use session challenge from DB)
        credential_data = verify_attestation(
             payload.attestation.model_dump(),
            payload.attestation.challenge,) 
         
    # TODO: Get challenge from session
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
        from app.security.webauthn.challenge import generate_challenge
        
        challenge = generate_challenge()
        
        # TODO: Get user credentials from DB
        # For now, return empty credential list
        
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
                # TODO: Populate from DB
                # {"id": credential_id, "type": "public-key"}
            ]
        }
    except Exception as e:
        logger.error(f"WebAuthn authentication start failed: {e}")
        raise HTTPException(status_code=400, detail="Authentication failed")


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

    Verifies assertion and creates grant (not session).

    Returns JWT grant token for accessing protected resources.
    """
    try:
        from datetime import datetime
        from app.security.webauthn.assertion import verify_assertion
        from app.security.webauthn.models import WebAuthnCredential

        #
        # TEMPORARY IMPLEMENTATION
        #
        # TODO:
        # Lookup credential by payload.credential_id from database.
        #

        credential = WebAuthnCredential(
            credential_id=payload.credential_id.encode(),
            public_key=b"temporary-public-key",
            sign_count=0,
            hardware_backed=True,
            attestation_verified=True,
            attestation_type="basic",
            created_at=datetime.utcnow(),
            last_used_at=datetime.utcnow(),
            revoked=False,
        )

        assertion_data = payload.assertion.model_dump()

        verify_assertion(
        assertion_data,
        credential,
         )

        logger.info(
            "WebAuthn authentication successful",
            extra={
                "email": payload.email,
                "credential_id": payload.credential_id,
                "event": "webauthn_auth_success",
            },
        )

        return {
            "status": "authenticated",
            "grant_id": "grant-placeholder",
            "access_token": "jwt-token-placeholder",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

    except Exception as e:
        logger.error(
            f"WebAuthn authentication failed: {e}"
        )

        raise HTTPException(
            status_code=401,
            detail="Authentication failed",
        )