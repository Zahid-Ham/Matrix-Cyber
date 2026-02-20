"""
Matrix - Agent-Driven Cyber Threat Simulator
Main FastAPI Application
"""
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

# Local imports
from config import get_settings
from core.database import init_db, close_db
from core.csrf import CSRFMiddleware
from core.api_limiter import limiter
from core.logger import get_logger
from core.security import create_csrf_token, verify_csrf_token

# API Routers
from api import (
    auth_router, scans_router, vulnerabilities_router, 
    chatbot_router, forensics_router, test_bench, 
    github_settings_router, exploit, exploit_explanation
)
from marketplace_simulation.controllers.marketplace_router import router as marketplace_router

# Initialize
logger = get_logger(__name__)
settings = get_settings()

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds essential security headers to all responses."""
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        if not settings.debug:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:;"
            
        return response

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("Starting Matrix Application...")
    await init_db()
    logger.info("[Main] Database initialized")
    yield
    logger.info("🔄 Shutting down Matrix...")
    await close_db()
    logger.info("✅ Cleanup complete")

app = FastAPI(
    title="Matrix",
    description="Agent-Driven Cyber Threat Simulator",
    version="1.1.0",
    lifespan=lifespan
)

# --- MIDDLEWARE CHAIN ---

# 1. Logging Middleware (Outermost)
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    path = request.url.path
    method = request.method
    logger.info(f"DEBUG-REQ: {method} {path}")
    
    try:
        response = await call_next(request)
        duration = (time.time() - start_time) * 1000
        logger.info(f"DEBUG-RES: {method} {path} - {response.status_code} ({duration:.2f}ms)")
        return response
    except Exception as e:
        logger.error(f"CRITICAL-FAIL: {method} {path} - Error: {str(e)}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal Server Error", "error": str(e) if settings.debug else "See server logs"}
        )

# 2. Security & Rate Limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

# 3. CORS
origins = [origin.strip() for origin in settings.allowed_origins.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins + ["http://localhost:3000", "http://127.0.0.1:3000", "http://35.226.18.153:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 4. CSRF (Manual check via endpoint + middleware)
app.add_middleware(CSRFMiddleware)

# --- ROUTES ---

@app.get("/api/csrf/", tags=["Security"])
async def get_csrf_token(request: Request, response: Response):
    """Sets/Returns CSRF token for the frontend security handshake."""
    token = request.cookies.get("CSRF-TOKEN")
    if not token or not verify_csrf_token(token):
        token = create_csrf_token()
        response.set_cookie(
            key="CSRF-TOKEN",
            value=token,
            httponly=False,
            samesite="lax",
            secure=False,
            path="/"
        )
    return {"status": "ok", "csrf_token": token}

@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "ok", "message": "Matrix API is operational"}

@app.get("/", tags=["Info"])
async def root():
    return {"name": "Matrix API", "version": "1.1.0", "status": "Online"}

# Register Routers
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

# Global Error Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"GLOBAL-ERROR on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred", "error": str(exc) if settings.debug else "Check records"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=settings.debug)
