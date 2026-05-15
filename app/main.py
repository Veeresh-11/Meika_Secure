import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

from app.api.health import router as health_router
from app.api.auth import router as auth_router
from app.security.bootstrap import build_pipeline
from app.security.middleware import security_middleware

load_dotenv()

app = FastAPI(title="Meika Secure ID")

# Initialize security pipeline once
pipeline = build_pipeline()

# Routers
app.include_router(health_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1")


# --------------------
# Basic Endpoints
# --------------------
@app.get("/")
def root():
    return {"status": "running"}


@app.get("/health")
def health():
    return {"status": "ok"}


# --------------------
# Device Context Resolver
# --------------------
def resolve_device_context(request: Request):
    return {
        "device_id": request.headers.get("X-Device-ID", "unknown"),
        "user_agent": request.headers.get("User-Agent"),
        "ip_address": request.client.host if request.client else "0.0.0.0",
    }

# ✅ 1. ADD SECURITY HEADERS MIDDLEWARE HERE
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"

    response.headers["Strict-Transport-Security"] = (
        "max-age=63072000; includeSubDomains; preload"
    )

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

    response.headers["Referrer-Policy"] = "no-referrer"

    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=()"
    )

    return response

# --------------------
# Security Middleware
# --------------------
@app.middleware("http")
async def enforce_security(request: Request, call_next):
    path = request.url.path

    # ✅ 1. CI BYPASS (for scanners like ZAP, Schemathesis)
    if os.getenv("CI_SECURITY_BYPASS") == "1":
        return await call_next(request)

    # ✅ 2. Always allow public + scanning endpoints
    if path in [
        "/", 
        "/health", 
        "/api/v1/health",
        "/openapi.json",   # 🔥 critical for ZAP
        "/docs",           # Swagger UI
        "/redoc",          # ReDoc UI
    ]:
        return await call_next(request)

    try:
        # Extract context once
        ctx = resolve_device_context(request)

        # Zero-trust enforcement
        if ctx["device_id"] == "unknown":
            raise Exception("Untrusted device")

        # Run security pipeline
        await security_middleware(
            request=request,
            pipeline=pipeline,
            get_device_context=lambda _: ctx,
        )

    except Exception as e:
        return JSONResponse(
            status_code=403,
            content={
                "error": "Security validation failed",
                "details": str(e),
            },
        )

    return await call_next(request)