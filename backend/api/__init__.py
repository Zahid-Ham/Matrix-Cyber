"""API routes package."""
from .auth import router as auth_router
from .scans import router as scans_router
from .vulnerabilities import router as vulnerabilities_router
from .chatbot import router as chatbot_router
from .forensics import router as forensics_router
from .test_bench import router as test_bench
from .github_settings import router as github_settings_router

__all__ = ["auth_router", "scans_router", "vulnerabilities_router", "chatbot_router", "forensics_router", "test_bench", "github_settings_router"]
