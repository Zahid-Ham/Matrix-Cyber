import secrets
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from core.logger import get_logger

CSRF_COOKIE_NAME = "CSRF-TOKEN"
CSRF_HEADER_NAME = "X-CSRF-Token"

logger = get_logger(__name__)

from core.security import create_csrf_token, verify_csrf_token

class CSRFMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        # 1. GET/HEAD/OPTIONS: Safe methods. Ensure Cookie is set.
        if request.method in ("GET", "HEAD", "OPTIONS"):
            response = await call_next(request)
            
            # Ensure cookie is set on all safe requests
            logger.info(f"Ensuring CSRF cookie for {request.url.path} (status: {response.status_code})")
            
            # Use signed token
            csrf_token = request.cookies.get(CSRF_COOKIE_NAME)
            if not csrf_token or not verify_csrf_token(csrf_token):
                csrf_token = create_csrf_token()
            
            response.set_cookie(
                key=CSRF_COOKIE_NAME,
                value=csrf_token,
                httponly=False,  # Must be False so JavaScript can read it
                samesite="none",  # Required for cross-origin (Vercel -> Render)
                secure=True,      # Required when SameSite=None
                path="/"
            )
            return response

        # 2. POST/PUT/DELETE/PATCH: Unsafe. Verify Header.
        logger.info(f"Checking CSRF for {request.url.path}")
        
        csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
        csrf_header = request.headers.get(CSRF_HEADER_NAME)

        # In cross-site context, cookies might be blocked. 
        # If we have a header and it's a valid SIGNED token, we trust it.
        if csrf_header and verify_csrf_token(csrf_header):
            # If cookie is also present, they MUST match (protection against token substitution)
            if csrf_cookie and csrf_cookie != csrf_header:
                logger.warning(f"CSRF token mismatch for {request.url.path}")
                return JSONResponse(
                    status_code=403,
                    content={"detail": "CSRF token missing or incorrect (Mismatch)"}
                )
            
            logger.info("CSRF verified via signed header token")
            return await call_next(request)

        # Fallback to old behavior if header is missing or invalid
        if not csrf_cookie:
            logger.warning(f"CSRF cookie missing for {request.url.path}. Expected cookie: {CSRF_COOKIE_NAME}")
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token missing or incorrect (Cookie missing)"}
            )
        
        if not csrf_header:
            logger.warning(f"CSRF header missing for {request.url.path}")
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token missing or incorrect (Header missing)"}
            )
            
        if csrf_cookie != csrf_header:
            logger.warning(f"CSRF token mismatch for {request.url.path}")
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token missing or incorrect (Mismatch)"}
            )
            
        return await call_next(request)
