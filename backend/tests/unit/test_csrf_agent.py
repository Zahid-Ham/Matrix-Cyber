"""
CSRF Agent Unit Tests
"""
import pytest
import asyncio
import re
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from agents.csrf_agent import CSRFAgent, CSRFConfig, CSRFProtectionType, CSRFTokenInfo
from models.vulnerability import Severity, VulnerabilityType
from scoring.vulnerability_context import VulnerabilityContext

# Use our custom markers
pytestmark = [pytest.mark.asyncio, pytest.mark.unit]

@pytest.fixture
def csrf_agent():
    return CSRFAgent()

class TestCSRFDetection:
    """Test CSRF vulnerability detection logic."""

    @pytest.mark.asyncio
    async def test_missing_csrf_protection(self, csrf_agent):
        """Verify detection of missing CSRF protection on state-changing endpoints."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Successfully updated profile"
        
        endpoint = {"url": "http://target.local/update", "method": "POST", "params": {"email": "test@local"}}
        
        with patch.object(csrf_agent, 'make_request', return_value=mock_resp):
            result = await csrf_agent._test_missing_protection(
                url="http://target.local/update",
                method="POST",
                endpoint=endpoint,
                protection_analysis={"type": CSRFProtectionType.NONE}
            )
            
            assert result is not None
            assert result.is_vulnerable is True
            assert result.severity == Severity.MEDIUM
            assert "Missing CSRF Protection" in result.title

    @pytest.mark.asyncio
    async def test_token_bypass_missing(self, csrf_agent):
        """Verify CSRF bypass when token is missing from request."""
        token_info = CSRFTokenInfo(
            value="valid_token_123",
            location="html",
            field_name="csrf_token",
            entropy=4.0,
            length=16,
            is_weak=False
        )
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Success"
        
        endpoint = {"url": "http://target.local/post", "method": "POST", "params": {}}
        protection_analysis = {"type": CSRFProtectionType.SYNCHRONIZER_TOKEN, "token_info": token_info}
        
        with patch.object(csrf_agent, 'make_request', return_value=mock_resp):
            results = await csrf_agent._test_token_bypass(
                url="http://target.local/post",
                method="POST",
                endpoint=endpoint,
                protection_analysis=protection_analysis
            )
            
            assert len(results) > 0
            assert any("Bypass" in r.title for r in results)
            assert results[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_weak_token_detection(self, csrf_agent):
        """Verify detection of weak/predictable CSRF tokens."""
        # Short and numeric only
        token_info = CSRFTokenInfo(
            value="1234567890123456", # Length 16 but numeric (weak)
            location="html",
            field_name="csrf",
            entropy=1.5,
            length=16,
            is_weak=False
        )
        
        result = await csrf_agent._test_token_strength(
            url="http://target.local",
            method="POST",
            token_info=token_info
        )
        
        assert result is not None
        assert result.is_vulnerable is True
        assert "Weak CSRF Token" in result.title
        # Severity for weak token is usually MEDIUM
        assert result.severity == Severity.MEDIUM

class TestCSRFMisconfigs:
    """Test global CSRF-related misconfigurations."""

    @pytest.mark.asyncio
    async def test_missing_samesite_attribute(self, csrf_agent):
        """Verify detection of missing SameSite attribute on session cookies."""
        mock_resp = MagicMock()
        mock_resp.headers = {"set-cookie": "sessionid=xyz123; HttpOnly; Secure"}
        
        with patch.object(csrf_agent, 'make_request', return_value=mock_resp):
            result = await csrf_agent._check_samesite_cookies("http://target.local")
            
            assert result is not None
            assert result.is_vulnerable is True
            assert "Missing SameSite Attribute" in result.title
            assert result.severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_cors_misconfig_csrf(self, csrf_agent):
        """Verify detection of CORS misconfiguration that enables CSRF."""
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Access-Control-Allow-Origin": CSRFConfig.TEST_ORIGIN,
            "Access-Control-Allow-Credentials": "true"
        }
        
        with patch.object(csrf_agent, 'make_request', return_value=mock_resp):
            result = await csrf_agent._check_cors_misconfiguration("http://target.local")
            
            assert result is not None
            assert result.is_vulnerable is True
            assert "CORS Misconfiguration" in result.title
            assert result.severity == Severity.MEDIUM

class TestCSRFCVSS:
    """Test CVSS scoring for CSRF vulnerabilities."""

    def test_csrf_cvss_impact(self, csrf_agent):
        """Verify CVSS for standard CSRF."""
        from scoring.cvss_calculator import CVSSCalculator
        
        ctx = csrf_agent._build_csrf_context(
            url="http://target.local/transfer",
            method="POST",
            endpoint={},
            description="State-changing action without CSRF protection"
        )
        
        calculator = CVSSCalculator()
        res = calculator.calculate(ctx)
        
        # S:U, UI:R, PR:N, C:N, I:L/H? 
        # By default CSRF in Matrix: I:L -> score around 4.3 (Medium)
        # If we want it High, we need to ensure I:H or S:C (SSRF/XSS)
        # Standard CSRF is usually Medium-High.
        assert 4.0 <= res.score <= 9.0
        assert res.severity in ["Medium", "High"]
