from app.api.health import router as health_router
from app.api.auth import router as auth_router
from app.security.bootstrap import build_pipeline
from fastapi import FastAPI, Request
from app.security.middleware import security_middleware


app = FastAPI(title="Meika Secure ID")
pipeline = build_pipeline()

app.include_router(health_router, prefix="/health")
app.include_router(auth_router)

@app.get("/")
def root():
    return {"status": "Meika Secure ID running"}

security_pipeline = build_pipeline()

@app.get("/health")
def health():
    return {"status": "ok"}

@app.middleware("http")
async def enforce_security(request: Request, call_next):
    try:
        await security_middleware(
            request=request,
            pipeline=pipeline,
            get_device_context=resolve_device_context,  # you already have this
        )
    except Exception as e:
        return JSONResponse(status_code=403, content={"error": str(e)})

    return await call_next(request)
