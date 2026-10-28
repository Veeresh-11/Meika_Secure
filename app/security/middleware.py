from datetime import datetime, timezone
import uuid

from fastapi import Request

from app.security.context import SecurityContext
from app.security.device_binding import resolve_registered_device_binding
from app.security.errors import SecurityError
from app.security.pipeline import SecurityPipeline


async def security_middleware(
    request: Request,
    pipeline: SecurityPipeline,
    get_device_context,
):
    """Final security enforcement layer for protected requests."""

    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise SecurityError("Missing authorization token")

    token = auth.split(" ", 1)[1]
    request_device_context = get_device_context(request)

    if isinstance(request_device_context, dict):
        requested_device_identifier = request_device_context.get("device_id")
    else:
        requested_device_identifier = getattr(
            request_device_context, "device_id", None
        )

    # Resolve the key from persisted active credentials. Never hash request
    # metadata or a client-supplied identifier as if it were public-key bytes.
    binding = resolve_registered_device_binding(
        token=token,
        requested_device_identifier=requested_device_identifier,
    )

    ctx = SecurityContext(
        request_id=str(uuid.uuid4()),
        principal_id=binding.payload["sub"],
        intent=f"{request.method} {request.url.path}",
        authenticated=True,
        device_id=binding.device.device_id,
        device=binding.device,
        risk_signals={},
        request_time=datetime.now(timezone.utc).replace(tzinfo=None),
        metadata={
            "ip": request.client.host if request.client else None,
            "ua": request.headers.get("user-agent"),
        },
    )

    decision = pipeline.evaluate(ctx)
    if decision.outcome.name != "ALLOW":
        raise SecurityError(decision.reason)

    request.state.security_context = ctx
    return ctx
