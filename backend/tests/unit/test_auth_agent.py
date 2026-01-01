"""
Authentication Agent Unit Tests
"""
import pytest
import asyncio
import time
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from agents.auth_agent import AuthenticationAgent, TimingResult
from models.vulnerability import Severity, VulnerabilityType
from scoring.vulnerability_context import VulnerabilityContext

# Use our custom markers
pytestmark = [pytest.mark.asyncio, pytest.mark.unit]

@pytest.fixture
def auth_agent():
    return AuthenticationAgent()

class TestAuthDetection:
    """Test authentication vulnerability detection logic."""

    @pytest.mark.asyncio
    async def test_default_credentials_detection(self, auth_agent):
        """Verify detection of working default credentials."""
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.text = "<html>Redirecting to dashboard... Logout</html>"
        mock_resp.headers = {"Set-Cookie": "session=abc123"}
        
        with patch.object(auth_agent, 'make_request', return_value=mock_resp):
            # Test with an entry from DEFAULT_CREDENTIALS
            result = await auth_agent._test_default_credentials(
                endpoint={"url": "http://test.local/login"},
                credentials=[("admin", "admin")]
            )
            
            assert result is not None
            assert result.is_vulnerable is True
            assert result.severity == Severity.CRITICAL
            assert "Default Credentials" in result.title

    @pytest.mark.asyncio
    async def test_username_enumeration_error(self, auth_agent):
        """Verify detection of username enumeration via error messages."""
        
        async def mock_request(url, method=None, data=None, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            if data and data.get("username") == "admin":
                resp.text = "Invalid password" # Specific password error
            else:
                resp.text = "User not found" # Specific user error
            return resp

        with patch.object(auth_agent, 'make_request', side_effect=mock_request):
            result = await auth_agent._test_username_enumeration(
                endpoint={"url": "http://test.local/login"}
            )
            
            assert result is not None
            assert result.is_vulnerable is True
            assert "Enumeration" in result.title

    @pytest.mark.asyncio
    async def test_username_enumeration_timing(self, auth_agent):
        """Verify detection of timing-based username enumeration."""
        
        async def mock_request(url, method=None, data=None, **kwargs):
            return MagicMock(status_code=200, text="Invalid credentials")

        # Mock timing: admin takes 0.5s, ghost takes 0.05s
        with patch.object(auth_agent, 'make_request', side_effect=mock_request):
            with patch("agents.auth_agent.time.time") as mock_time:
                # Enough values for init call, loop calls, and logging/overhead
                # 1 (init) + 4 iterations * 2 calls + 20+ for logging = 50+
                mock_time.side_effect = [
                    100.0, # f-string call
                    100.0, 100.5,   # admin -> 0.5s
                    101.0, 101.5,   # administrator -> 0.5s
                    102.0, 102.05,  # invalid_1 -> 0.05s
                    103.0, 103.05   # invalid_2 -> 0.05s
                ] + [104.0] * 50
                
                result = await auth_agent._test_timing_enumeration(
                    endpoint={"url": "http://test.local/login"}
                )
                
                assert result is not None
                assert "Timing" in result.title
                assert result.is_vulnerable is True

    @pytest.mark.asyncio
    async def test_weak_password_registration(self, auth_agent):
        """Verify detection of weak password acceptance."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.text = "Account successfully created! Welcome."
        
        with patch.object(auth_agent, 'make_request', return_value=mock_resp):
            result = await auth_agent._test_weak_passwords(
                endpoint={"url": "http://test.local/login"}
            )
            
            assert result is not None
            assert result.is_vulnerable is True
            assert "Weak Password" in result.title

class TestAuthSecurity:
    """Test secondary authentication security checks."""

    @pytest.mark.asyncio
    async def test_rate_limiting_missing(self, auth_agent):
        """Verify detection of missing rate limiting."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Invalid credentials"
        
        # Always return success (no 429)
        with patch.object(auth_agent, 'make_request', return_value=mock_resp):
            result = await auth_agent._test_rate_limiting(
                endpoint={"url": "http://test.local/login"}
            )
            
            assert result is not None
            assert result.is_vulnerable is True
            assert "Rate Limiting" in result.title

    @pytest.mark.asyncio
    async def test_insecure_session_cookies(self, auth_agent):
        """Verify detection of insecure cookie attributes."""
        mock_cookie = MagicMock()
        mock_cookie.name = "session_id"
        mock_cookie.value = "secret"
        # Mocking has_nonstandard_attr to return False for security flags
        mock_cookie.has_nonstandard_attr.return_value = False
        mock_cookie.secure = False
        
        mock_resp = MagicMock()
        mock_resp.cookies.jar = [mock_cookie]
        
        with patch.object(auth_agent, 'make_request', return_value=mock_resp):
            results = await auth_agent._check_session_cookies(
                url="http://test.local/"
            )
            
            assert len(results) > 0
            assert results[0].is_vulnerable is True
            assert "Insecure Session Cookie" in results[0].title

    @pytest.mark.asyncio
    async def test_jwt_detection(self, auth_agent):
        """Verify detection of JWT tokens in responses."""
        mock_resp = MagicMock()
        # Mock a JWT-like string
        mock_resp.text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        
        with patch.object(auth_agent, 'make_request', return_value=mock_resp):
            results = await auth_agent._test_token_security(
                target_url="http://test.local/",
                endpoints=[{"url": "http://test.local/api/auth"}]
            )
            
            assert len(results) > 0
            assert "JWT" in results[0].title

class TestAuthCVSS:
    """Test CVSS scoring for authentication vulnerabilities."""

    def test_broken_auth_cvss(self, auth_agent):
        """Verify CVSS for critical broken auth (default credentials)."""
        from scoring.cvss_calculator import CVSSCalculator
        
        ctx = auth_agent._build_auth_context(
            url="http://test.local/login",
            vulnerability_type="default_credentials",
            description="Default admin credentials accepted"
        )
        
        calculator = CVSSCalculator()
        res = calculator.calculate(ctx)
        
        # Breakdown: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8
        assert res.score >= 9.0
        assert res.severity == "Critical"

    def test_enumeration_cvss(self, auth_agent):
        """Verify CVSS for username enumeration."""
        from scoring.cvss_calculator import CVSSCalculator
        
        ctx = auth_agent._build_auth_context(
            url="http://test.local/login",
            vulnerability_type="username_enumeration",
            description="Found common usernames"
        )
        
        calculator = CVSSCalculator()
        res = calculator.calculate(ctx)
        
        # Enumeration is usually Medium/Low impact (C:L/I:N/A:N)
        assert 5.0 <= res.score <= 6.0
        assert res.severity == "Medium"
