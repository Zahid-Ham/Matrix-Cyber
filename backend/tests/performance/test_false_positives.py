"""
False Positive Validation Tests.
Ensures the scanner does not report vulnerabilities on secure, well-configured applications.
"""
import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from agents.orchestrator import AgentOrchestrator, AgentNames
from agents.base_agent import AgentResult, CachedResponse
from models.vulnerability import Severity, VulnerabilityType

@pytest.fixture
def orchestrator():
    return AgentOrchestrator()

class MockResponse:
    def __init__(self, text, status_code, headers):
        self.text = text
        self.status_code = status_code
        self.headers = headers
        self.content = text.encode()
        self.is_redirect = False
        self.url = "http://target.local"
    def json(self):
        import json
        return json.loads(self.text)

@pytest.mark.asyncio
async def test_django_secure_defaults(orchestrator):
    """Verify no findings on Django-style secure headers."""
    # Mocking a response with all common security headers
    secure_headers = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "same-origin",
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-XSS-Protection": "1; mode=block",
        "Permissions-Policy": "geolocation=(), microphone=()",
        "Server": "Gunicorn",
        "Set-Cookie": "sessionid=xyz; HttpOnly; Secure; SameSite=Lax"
    }
    
    async def mock_request(*args, **kwargs):
        return MockResponse("OK", 200, secure_headers)

    with patch("agents.base_agent.BaseSecurityAgent.make_request", side_effect=mock_request):
        results = await orchestrator.run_scan(
            target_url="https://secure-django.local",
            agents_enabled=[AgentNames.SECURITY_HEADERS],
            endpoints=[{"url": "https://secure-django.local", "method": "GET"}]
        )
        
        # Should not find missing headers or cookie issues
        findings = [r for r in results if r.severity != Severity.INFO]
        if len(findings) > 0:
            print(f"DEBUG: Found {len(findings)} Security Header findings")
            for f in findings:
                print(f"DEBUG FINDING: {f.title} (Severity: {f.severity})")
        assert len(findings) == 0

@pytest.mark.asyncio
async def test_laravel_csrf_protection(orchestrator):
    """Verify no CSRF findings when Laravel-style token protection is present."""
    import uuid
    # State-aware mock with high-entropy tokens
    state = {"issued_token": None, "used_tokens": set()}
    
    async def mock_csrf_request(url, method="GET", data=None, **kwargs):
        if method == "POST":
            token = (data or {}).get("_token") or (data or {}).get("csrf_token") or (data or {}).get("token")
            if not token and data:
                for k, v in data.items():
                    if "token" in k.lower() or "csrf" in k.lower():
                        token = v
                        break

            if not token:
                return MockResponse("Forbidden - CSRF Token Missing", 403, {})
            
            if token != state["issued_token"]:
                return MockResponse("Forbidden - Invalid Token", 403, {})
            
            if token in state["used_tokens"]:
                return MockResponse("Forbidden - Token Reused", 403, {})
            
            state["used_tokens"].add(token)
            return MockResponse("OK", 200, {})
        
        # GET returns form with high-entropy token (NOT 32 chars to avoid 'MD5' false positive)
        new_token = str(uuid.uuid4()).replace("-", "") + "securetoken123" # 32 + 14 = 46 chars
        state["issued_token"] = new_token
        resp_headers = {"Set-Cookie": f"XSRF-TOKEN={new_token}; Path=/; SameSite=Lax"}
        return MockResponse(f'<html><input type="hidden" name="_token" value="{new_token}"></html>', 200, resp_headers)

    with patch("agents.base_agent.BaseSecurityAgent.make_request", side_effect=mock_csrf_request):
        results = await orchestrator.run_scan(
            target_url="https://secure-laravel.local",
            agents_enabled=[AgentNames.CSRF],
            endpoints=[{"url": "https://secure-laravel.local", "method": "POST", "params": {"data": "test"}}]
        )
        
        csrf_findings = [r for r in results if r.vulnerability_type == VulnerabilityType.CSRF]
        if len(csrf_findings) > 0:
            print(f"DEBUG: Found {len(csrf_findings)} CSRF findings")
            for f in csrf_findings:
                print(f"DEBUG FINDING: {f.title} (Confidence: {f.confidence})")
        assert len(csrf_findings) == 0

@pytest.mark.asyncio
async def test_auth_timing_consistency(orchestrator):
    """Verify no timing enumeration when responses are consistent."""
    request_count = 0
    async def mock_request(*args, **kwargs):
        nonlocal request_count
        request_count += 1
        if request_count > 5: # Low threshold to ensure rate limiting is detected
            return MockResponse('{"error": "too many requests"}', 429, {"Retry-After": "60"})
        return MockResponse('{"error": "invalid login"}', 401, {})

    # Auth Agent and Base Agent together call time.time() 4 times per request.
    times = []
    base_time = 1700000000.0
    for i in range(1000):
        times.append(base_time + i)       # Start BaseRequest
        times.append(base_time + i + 0.1) # End BaseRequest
        times.append(base_time + i)       # Start AuthEnum
        times.append(base_time + i + 0.1) # End AuthEnum

    with patch("agents.base_agent.BaseSecurityAgent.make_request", side_effect=mock_request), \
         patch("time.time", side_effect=times):
        results = await orchestrator.run_scan(
            target_url="https://secure-auth.local",
            agents_enabled=[AgentNames.AUTH],
            endpoints=[{"url": "https://secure-auth.local/login", "method": "POST", "params": {"user": "admin", "pass": "123"}}]
        )
        
        timing_findings = [r for r in results if r.vulnerability_type == VulnerabilityType.BRUTE_FORCE_VULNERABLE or r.vulnerability_type == VulnerabilityType.BROKEN_AUTH]
        if len(timing_findings) > 0:
            vulnerabilities = [r for r in timing_findings if r.severity != Severity.INFO]
            if len(vulnerabilities) > 0:
                print(f"DEBUG: Found {len(vulnerabilities)} Auth vulnerabilities")
                for f in vulnerabilities:
                    print(f"DEBUG FINDING: {f.title} (Severity: {f.severity})")
            assert len(vulnerabilities) == 0
        else:
            assert len(timing_findings) == 0

@pytest.mark.asyncio
async def test_waf_blocking_detection(orchestrator):
    """Verify WAF blocks are not detected as vulnerabilities."""
    waf_headers = {"Server": "Cloudflare", "CF-RAY": "1234567890"}
    
    async def mock_request(*args, **kwargs):
        return MockResponse("Access Denied by WAF Security Policy", 403, waf_headers)

    with patch("agents.base_agent.BaseSecurityAgent.make_request", side_effect=mock_request):
        results = await orchestrator.run_scan(
            target_url="https://waf-protected.local",
            agents_enabled=[AgentNames.SQL_INJECTION, AgentNames.XSS],
            endpoints=[{"url": "https://waf-protected.local/search", "method": "GET", "params": {"q": "test"}}]
        )
        
        sqli_xss = [r for r in results if r.vulnerability_type in [VulnerabilityType.SQL_INJECTION, VulnerabilityType.XSS_REFLECTED]]
        assert len(sqli_xss) == 0
