"""
API Security Agent Unit Tests
"""
import pytest
import asyncio
import re
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from agents.api_security_agent import APISecurityAgent, APITestConfig
from models.vulnerability import Severity, VulnerabilityType
from scoring.vulnerability_context import VulnerabilityContext

# Use our custom markers
pytestmark = [pytest.mark.asyncio, pytest.mark.unit]

@pytest.fixture
def api_agent():
    return APISecurityAgent()

class TestAPIDetection:
    """Test API vulnerability detection logic."""

    @pytest.mark.asyncio
    async def test_data_exposure_detection(self, api_agent):
        """Verify detection of sensitive data in API responses."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"user": "admin", "password": "SuperSecretPassword123", "email": "admin@matrix.local"}'
        
        # Mock AI analysis for data exposure
        mock_ai = {"confidence": 90, "reason": "Explicit password field found in JSON response."}
        
        with patch.object(api_agent, 'make_request', return_value=mock_resp):
            with patch.object(api_agent, 'analyze_with_ai', return_value=mock_ai):
                result = await api_agent._test_data_exposure("http://api.local/users/1")
                
                assert result is not None
                assert result.is_vulnerable is True
                assert result.severity == Severity.HIGH
                assert "Excessive Data Exposure" in result.title
                assert "password" in result.description

    @pytest.mark.asyncio
    async def test_idor_bola_detection(self, api_agent):
        """Verify detection of BOLA/IDOR via numeric ID manipulation."""
        
        async def mock_request(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            if "users/1" in url:
                resp.text = '{"id": 1, "name": "User One"}'
            elif "users/2" in url:
                resp.text = '{"id": 2, "name": "User Two"}'
            else:
                resp.status_code = 404
                resp.text = "Not found"
            return resp

        endpoint = {"url": "http://api.local/users/1", "method": "GET"}
        
        with patch.object(api_agent, 'make_request', side_effect=mock_request):
            result = await api_agent._test_idor_enhanced(endpoint)
            
            assert result is not None
            assert result.is_vulnerable is True
            assert result.severity == Severity.HIGH
            assert "Broken Object Level Authorization" in result.title

    @pytest.mark.asyncio
    async def test_mass_assignment_detection(self, api_agent):
        """Verify detection of mass assignment vulnerabilities."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # Privileged field "is_admin" echoed back
        mock_resp.text = '{"id": 123, "username": "testuser", "is_admin": true}'
        
        with patch.object(api_agent, 'make_request', return_value=mock_resp):
            result = await api_agent._test_mass_assignment("http://api.local/profile/update", method="POST")
            
            assert result is not None
            assert result.is_vulnerable is True
            assert result.severity == Severity.HIGH
            assert "Mass Assignment" in result.title

    @pytest.mark.asyncio
    async def test_bfla_detection(self, api_agent):
        """Verify detection of Broken Function Level Authorization."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200 # Accessible without auth
        mock_resp.text = '{"system_status": "ok", "config": {...}}'
        
        # Test a privileged path
        target_url = "http://api.local"
        
        with patch.object(api_agent, 'make_request', return_value=mock_resp):
            results = await api_agent._test_function_level_authz(target_url)
            
            assert len(results) > 0
            assert any("BFLA" in r.title for r in results)
            assert results[0].severity == Severity.HIGH

class TestAPISecurityConfigs:
    """Test API security configuration checks."""

    @pytest.mark.asyncio
    async def test_rate_limiting_missing(self, api_agent):
        """Verify detection of missing rate limiting."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        
        # Simulate all requests succeeding
        with patch.object(api_agent, 'make_request', return_value=mock_resp):
            result = await api_agent._test_rate_limiting("http://api.local/search")
            
            assert result is not None
            assert result.is_vulnerable is True
            assert "Rate Limiting" in result.title

    @pytest.mark.asyncio
    async def test_improper_inventory_detection(self, api_agent):
        """Verify detection of multiple API versions (Improper Inventory)."""
        
        async def mock_request(url, **kwargs):
            resp = MagicMock()
            # Simulate v1, v2, v3 active
            if any(v in url for v in ["v1", "v2", "v3"]):
                resp.status_code = 200
            else:
                resp.status_code = 404
            return resp

        with patch.object(api_agent, 'make_request', side_effect=mock_request):
            results = await api_agent._check_old_api_versions("http://api.local/")
            
            assert len(results) > 0
            assert "Inventory" in results[0].title
            assert results[0].severity == Severity.LOW

class TestAPICVSS:
    """Test CVSS scoring for API vulnerabilities."""

    def test_idor_cvss(self, api_agent):
        """Verify CVSS for IDOR/BOLA."""
        from scoring.cvss_calculator import CVSSCalculator
        
        ctx = api_agent._build_api_context(
            url="http://api.local/users/5",
            vulnerability_type="bola_idor",
            description="Accessed other user details"
        )
        
        calculator = CVSSCalculator()
        res = calculator.calculate(ctx)
        
        # BOLA is High/Critical: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N -> 9.1
        assert res.score >= 8.0
        assert res.severity in ["High", "Critical"]

    def test_data_exposure_cvss(self, api_agent):
        """Verify CVSS for sensitive data exposure."""
        from scoring.cvss_calculator import CVSSCalculator
        
        ctx = api_agent._build_api_context(
            url="http://api.local/api/users",
            vulnerability_type="sensitive_data_exposure",
            description="Found cleartext passwords",
            data_exposed=["passwords"]
        )
        
        calculator = CVSSCalculator()
        res = calculator.calculate(ctx)
        
        # C:H -> score around 7.5
        assert 7.0 <= res.score <= 8.0
        assert res.severity == "High"
