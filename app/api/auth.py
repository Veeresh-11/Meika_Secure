from fastapi import APIRouter, Depends, HTTPException, Request, Body
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
# Request Models (STRICT VALIDATION)
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
# Registration (SAFE)
# -------------------------------------------------

@router.post("/register", responses={422: {"description": "Validation Error"}})
def register(payload: RegisterRequest = Body(...), db: Session = Depends(get_db)):

    try:
        user = AuthService.register_user(
            db=db,
            email=payload.email,
            password=payload.password,
            display_name=payload.display_name,
        )
    except Exception:
        # 🔒 Never expose internal errors
        raise HTTPException(status_code=400, detail="Invalid registration data")

    return {"user_id": str(user.id)}


# -------------------------------------------------
# Login (SAFE + ZERO TRUST)
# -------------------------------------------------

@router.post("/login", responses={422: {"description": "Validation Error"}})
def login(
    payload: LoginRequest = Body(...),
    request: Request = None,
    db: Session = Depends(get_db),
):

    # ---- Step 1: Validate required fields ----
    if not payload.email or not payload.password:
        raise HTTPException(status_code=400, detail="Missing credentials")

    # ---- Step 2: Verify credentials ----
    try:
        session = AuthService.login_user(
            db=db,
            email=payload.email,
            password=payload.password,
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid login request")

    if not session:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    principal_id = str(session.user_id)

    # ---- Step 3: Device Context ----
    try:
        device_ctx = DeviceContext(
            device_id=payload.device_id,
            registered=device_registry.is_registered(
                payload.device_id, principal_id
            ),
            posture=posture_evaluator.evaluate(payload.device_signals),
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid device context")

    # ---- Step 4: Security Context ----
    security_ctx = SecurityContext(
        principal_id=principal_id,
        authenticated=True,
        intent="user.login",
        device=device_ctx,
    )

    # ---- Step 5: Zero Trust Enforcement ----
    try:
        decision = pipeline.evaluate(security_ctx)
    except SecurityPipelineError:
        raise HTTPException(status_code=403, detail="Access denied")
    except Exception:
        raise HTTPException(status_code=400, detail="Security validation failed")

    # ---- Step 6: Response ----
    return {
        "session_id": str(session.id),
        "expires_at": session.expires_at,
        "decision": decision.outcome.value,
    }