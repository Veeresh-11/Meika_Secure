from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

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
# Registration (NO pipeline — identity creation only)
# -------------------------------------------------

@router.post("/register")
def register(payload: dict, db: Session = Depends(get_db)):
    user = AuthService.register_user(
        db=db,
        email=payload["email"],
        password=payload["password"],
        display_name=payload.get("display_name"),
    )
    return {"user_id": str(user.id)}


# -------------------------------------------------
# Login (AUTHENTICATION + ZERO TRUST ENFORCEMENT)
# -------------------------------------------------

@router.post("/login")
def login(payload: dict, request: Request, db: Session = Depends(get_db)):
    """
    Login is NOT trusted by itself.
    Password verification proves identity,
    but access is decided ONLY by the security pipeline.
    """

    # ---- Step 1: Verify credentials (identity proof) ----
    session = AuthService.login_user(
        db=db,
        email=payload["email"],
        password=payload["password"],
    )

    if not session:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    principal_id = str(session.user_id)
    intent = "user.login"

    # ---- Step 2: Collect device signals (NO TRUST) ----
    device_id = payload.get("device_id")
    raw_signals = payload.get("device_signals", {})

    if not device_id:
        raise HTTPException(status_code=400, detail="Missing device_id")

    # ---- Step 3: Build DeviceContext (evaluation only) ----
    device_ctx = DeviceContext(
        device_id=device_id,
        registered=device_registry.is_registered(device_id, principal_id),
        posture=posture_evaluator.evaluate(raw_signals),
    )

    # ---- Step 4: Build SecurityContext ----
    security_ctx = SecurityContext(
        principal_id=principal_id,
        authenticated=True,   # identity proof succeeded
        intent=intent,
        device=device_ctx,
    )

    # ---- Step 5: Enforce Zero Trust ----
    try:
        decision = pipeline.evaluate(security_ctx)
    except SecurityPipelineError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    # ---- Step 6: Return session info (still non-authoritative) ----
    return {
        "session_id": str(session.id),
        "expires_at": session.expires_at,
        "decision": decision.outcome.value,
    }

