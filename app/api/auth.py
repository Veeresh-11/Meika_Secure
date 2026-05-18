from fastapi import APIRouter, Depends, HTTPException, Request, Body
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, EmailStr

from app.db.session import SessionLocal
from app.services.auth_service import AuthService

from app.security.bootstrap import build_pipeline
from app.security.context import SecurityContext
from app.security.device.context import DeviceContext
from app.security.device.registry import DeviceRegistry
from app.security.device.posture import DevicePostureEvaluator
from app.security.errors import SecurityPipelineError


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
# Models (STRICT & CORRECT)
# --------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=10)
    display_name: str | None = Field(default=None, min_length=1)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=10)
    device_id: str = Field(..., min_length=3)
    device_signals: dict = Field(default_factory=dict)


# --------------------
# Register
# --------------------

@router.post(
    "/register",
    responses={
        200: {"description": "Success"},
        409: {"description": "User already exists"},
        500: {"description": "Internal error"},
        422: {"description": "Validation Error"},
    },
)
def register(payload: RegisterRequest = Body(...), db: Session = Depends(get_db)):

    try:
        user = AuthService.register_user(
            db=db,
            email=payload.email,
            password=payload.password,
            display_name=payload.display_name,
        )
    except Exception:
        # 🔥 FIX: DO NOT return 400
        raise HTTPException(status_code=500, detail="Registration failed")

    return {"user_id": str(user.id)}


# --------------------
# Login
# --------------------

@router.post(
    "/login",
    responses={
        200: {"description": "Success"},
        401: {"description": "Invalid credentials"},
        403: {"description": "Access denied"},
        500: {"description": "Internal error"},
        422: {"description": "Validation Error"},
    },
)
def login(
    payload: LoginRequest = Body(...),
    request: Request = None,
    db: Session = Depends(get_db),
):

    # ---- Step 1: Authenticate ----
    try:
        session = AuthService.login_user(
            db=db,
            email=payload.email,
            password=payload.password,
        )
    except Exception:
        # 🔥 FIX: DO NOT return 400
        raise HTTPException(status_code=500, detail="Login processing failed")

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
        raise HTTPException(status_code=500, detail="Security pipeline failure")

    return {
        "session_id": str(session.id),
        "expires_at": session.expires_at,
        "decision": decision.outcome.value,
    }