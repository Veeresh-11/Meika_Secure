from fastapi import Request
from app.security.tokens.enforce import enforce_device_bound_token
from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext
from app.security.errors import SecurityError
from datetime import datetime
import uuid


async def security_middleware(
    request: Request,
    pipeline: SecurityPipeline,
    get_device_context,
):
    """
    This middleware is the FINAL authority.
    If this allows → request proceeds.
    Otherwise → request is terminated.
    """

    # 1️⃣ Extract token
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise SecurityError("Missing authorization token")

    token = auth.split(" ", 1)[1]

    # 2️⃣ Resolve device context (from DB / cache)
    device_ctx = get_device_context(request)

    # 3️⃣ Enforce token ↔ device binding
    enforce_device_bound_token(
        token=token,
        device_public_key=device_ctx.identity_public_key,
    )

    # 4️⃣ Build SecurityContext
    ctx = SecurityContext(
        request_id=str(uuid.uuid4()),
        principal_id=device_ctx.principal_id,
        intent=request.method + " " + request.url.path,
        authenticated=True,
        device_id=device_ctx.device_id,
        device=device_ctx,
        risk_signals={},
        request_time=datetime.utcnow(),
        metadata={
            "ip": request.client.host if request.client else None,
            "ua": request.headers.get("user-agent"),
        },
    )

    # 5️⃣ Policy evaluation (non-negotiable)
    decision = pipeline.evaluate(ctx)
    if decision.outcome.name != "ALLOW":
        raise SecurityError(decision.reason)

    return ctx  # attach to request.state if desired

# at the end of security_middleware
request.state.security_context = ctx
return ctx
