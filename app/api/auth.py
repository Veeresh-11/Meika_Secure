from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.db.session import SessionLocal
from app.services.auth_service import AuthService

from app.security.bootstrap import build_pipeline
from app.security.context import SecurityContext
from app.security.device.context import DeviceContext
from app.security.device.registry import DeviceRegistry
from app.security.device.posture import DevicePostureEvaluator
from app.security.errors import SecurityPipelineError


router = APIRouter(prefix="/auth")

# -------------------------------------------------
# Infrastructure
# -------------------------------------------------

pipeline = build_pipeline()
device_registry = DeviceRegistry()
posture_evaluator = DevicePostureEvaluator()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -------------------------------------------------
# Request Models (FIX: validation)
# -------------------------------------------------

class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=5)
    password: str = Field(..., min_length=6)
    display_name: str | None = None


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=5)
    password: str = Field(..., min_length=6)
    device_id: str = Field(..., min_length=3)
    device_signals: dict = Field(default_factory=dict)


# -------------------------------------------------
# Registration
# -------------------------------------------------

@router.post("/register", responses={422: {"description": "Validation Error"}})
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    user = AuthService.register_user(
        db=db,
        email=payload.email,
        password=payload.password,
        display_name=payload.display_name,
    )
    return {"user_id": str(user.id)}


# -------------------------------------------------
# Login
# -------------------------------------------------

@router.post("/login", responses={422: {"description": "Validation Error"}})
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):

    # ---- Step 1: Verify credentials ----
    session = AuthService.login_user(
        db=db,
        email=payload.email,
        password=payload.password,
    )

    if not session:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    principal_id = str(session.user_id)

    # ---- Step 2: Device context ----
    device_ctx = DeviceContext(
        device_id=payload.device_id,
        registered=device_registry.is_registered(payload.device_id, principal_id),
        posture=posture_evaluator.evaluate(payload.device_signals),
    )

    # ---- Step 3: Security context ----
    security_ctx = SecurityContext(
        principal_id=principal_id,
        authenticated=True,
        intent="user.login",
        device=device_ctx,
    )

    # ---- Step 4: Zero Trust enforcement ----
    try:
        decision = pipeline.evaluate(security_ctx)
    except SecurityPipelineError:
        raise HTTPException(status_code=403, detail="Access denied")

    # ---- Step 5: Response ----
    return {
        "session_id": str(session.id),
        "expires_at": session.expires_at,
        "decision": decision.outcome.value,
    }