"""
Matrix - Agent-Driven Cyber Threat Simulator
Main FastAPI Application (Restored Alignment with Backup)
"""
import secrets
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from config import get_settings
from core.database import init_db, close_db
from core.csrf import CSRFMiddleware
from core.api_limiter import limiter
from api import auth_router, scans_router, vulnerabilities_router, chatbot_router, forensics_router, test_bench, github_settings_router, exploit, exploit_explanation
from marketplace_simulation.controllers.marketplace_router import router as marketplace_router
from agents.orchestrator import orchestrator

settings = get_settings()

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
        
        if not settings.debug:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; upgrade-insecure-requests"
            
        return response

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Starting Matrix...")
    await init_db()
    print("[Main] Database initialized")
    yield
    print("🔄 Shutting down Matrix...")
    await close_db()
    print("✅ Cleanup complete")

app = FastAPI(
    title="Matrix",
    description="Agent-Driven Cyber Threat Simulator",
    version="1.0.0",
    lifespan=lifespan,
)

# Initialize Rate Limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CSRFMiddleware) 
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

# Simple CORS matching backup
origins = [origin.strip() for origin in settings.allowed_origins.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins + ["http://localhost:3000", "http://127.0.0.1:3000", "http://35.226.18.153:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "ok", "message": "Matrix API is operational"}

@app.get("/api/csrf/", tags=["Security"])
async def get_csrf_init(request: Request, response: Response):
    from core.security import create_csrf_token, verify_csrf_token
    csrf_token = request.cookies.get("CSRF-TOKEN")
    
    if not csrf_token or not verify_csrf_token(csrf_token):
        csrf_token = create_csrf_token()
        response.set_cookie(
            key="CSRF-TOKEN",
            value=csrf_token,
            httponly=False,
            samesite="lax",
            secure=False,
            path="/"
        )
    
    return {
        "status": "CSRF initialized",
        "csrf_token": csrf_token,
        "app": settings.app_name,
        "version": "1.0.0"
    }

@app.get("/", tags=["Info"])
async def root():
    return {"name": "Matrix API", "version": "1.0.0"}

# Register routers
app.include_router(auth_router, prefix="/api")
app.include_router(scans_router, prefix="/api")
app.include_router(vulnerabilities_router, prefix="/api")
app.include_router(chatbot_router, prefix="/api")
app.include_router(forensics_router, prefix="/api")
app.include_router(github_settings_router, prefix="/api")
app.include_router(marketplace_router, prefix="/api")
app.include_router(test_bench, prefix="/api")
app.include_router(exploit.router, prefix="/api")
app.include_router(exploit_explanation.router, prefix="/api")

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    import logging
    logging.error(f"Global error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error", "error": str(exc)}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=settings.debug)
