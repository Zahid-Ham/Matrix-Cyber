import secrets
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from core.logger import get_logger

CSRF_COOKIE_NAME = "CSRF-TOKEN"
CSRF_HEADER_NAME = "X-CSRF-Token"

logger = get_logger(__name__)

class CSRFMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        # 1. GET/HEAD/OPTIONS: Safe methods. Ensure Cookie is set.
        if request.method in ("GET", "HEAD", "OPTIONS"):
            response = await call_next(request)
            
            # Ensure cookie is set on all safe requests (even if 401/405/etc)
            # This is critical so we have a token for the subsequent login/action
            logger.info(f"Ensuring CSRF cookie for {request.url.path} (status: {response.status_code})")
            
            csrf_token = request.cookies.get(CSRF_COOKIE_NAME) or secrets.token_urlsafe(32)
            
            response.set_cookie(
                key=CSRF_COOKIE_NAME,
                value=csrf_token,
                httponly=False,  # Must be False so JavaScript can read it
                samesite="none",  # Required for cross-origin (Vercel -> Render)
                secure=True,      # Required when SameSite=None
                path="/"
            )
            return response

        # 2. POST/PUT/DELETE/PATCH: Unsafe. Verify Header matches Cookie.
        logger.info(f"Checking CSRF for {request.url.path}")
        logger.info(f"Headers: {dict(request.headers)}")
        logger.info(f"Cookies: {dict(request.cookies)}")
        
        csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
        csrf_header = request.headers.get(CSRF_HEADER_NAME)

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
