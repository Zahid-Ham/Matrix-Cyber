"""
SSRF Agent Unit Tests
"""
import pytest
import asyncio
import time
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from agents.ssrf_agent import SSRFAgent, SSRFTestResult
from models.vulnerability import Severity, VulnerabilityType
from scoring.vulnerability_context import VulnerabilityContext

# Use our custom markers
pytestmark = [pytest.mark.asyncio, pytest.mark.unit]

@pytest.fixture
def ssrf_agent():
    return SSRFAgent()

class TestSSRFDetection:
    """Test standard SSRF detection logic."""

    @pytest.mark.asyncio
    async def test_cloud_metadata_detection(self, ssrf_agent):
        """Verify detection of cloud metadata endpoint access."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"ami-id": "ami-12345678", "instance-id": "i-12345678"}'
        
        with patch.object(ssrf_agent, 'make_request', return_value=mock_resp):
            result = await ssrf_agent._test_cloud_metadata(
                url="http://test.local/proxy",
                method="GET",
                params={"u": "http://google.com"},
                param_name="u"
            )
            
            assert result is not None
            assert result.is_vulnerable is True
            assert "AWS" in result.description
            assert result.severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_localhost_detection(self, ssrf_agent):
        """Verify detection of localhost access via variations."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><body>Localhost Dashboard - This response is long enough to bypass length checks and satisfy the agent's criteria for a successful SSRF finding.</body></html>"
        
        with patch.object(ssrf_agent, 'make_request', return_value=mock_resp):
# ... (rest of method)
            # Test with a localhost variation
            result = await ssrf_agent._test_single_payload(
                url="http://test.local/proxy",
                method="GET",
                params={"u": "valid"},
                param_name="u",
                payload="http://127.0.0.1/"
            )
            
            assert result is not None
            assert result.is_vulnerable is True

    @pytest.mark.asyncio
    async def test_protocol_handler_detection(self, ssrf_agent):
        """Verify detection of dangerous protocol handlers."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "root:x:0:0:root:/root:/bin/bash"
        
        with patch.object(ssrf_agent, 'make_request', return_value=mock_resp):
            result = await ssrf_agent._test_protocol_handlers(
                url="http://test.local/view",
                method="GET",
                params={"file": "test.txt"},
                param_name="file"
            )
            
            assert result is not None
            assert result.is_vulnerable is True
            assert "protocol" in result.description.lower()
            assert "file" in result.payload

class TestSSRFBypasses:
    """Test SSRF bypass techniques."""

    @pytest.mark.asyncio
    async def test_encoding_bypasses(self, ssrf_agent):
        """Verify detection when URL encoding is required."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><body>Some data that is long enough to bypass the 50 character length check used by the agent detection logic. This should ensure the test passes.</body></html>"
        
        # Mock make_request to only succeed if the payload is encoded (simulating a filter bypass)
        async def mock_request(url, params=None, **kwargs):
            if params and "%2e" in params.get("u", ""):
                return mock_resp
            return None

        with patch.object(ssrf_agent, 'make_request', side_effect=mock_request):
            result = await ssrf_agent._test_bypass_techniques(
                url="http://test.local/proxy",
                method="GET",
                params={"u": "http://google.com"},
                param_name="u"
            )
            
            assert result is not None
            assert result.is_vulnerable is True
            assert "encoding" in result.description.lower()

class TestSSRFBlind:
    """Test blind SSRF detection."""

    @pytest.mark.asyncio
    async def test_timing_based_blind_ssrf(self, ssrf_agent):
        """Verify timing-based blind SSRF detection."""
        # Baseline: 0.1s
        # Slow target: 12.0s (greater than TIMEOUT_THRESHOLD=10)
        
        timing = {"count": 0}
        async def mock_time_request(*args, **kwargs):
            timing["count"] += 1
            if timing["count"] > 3: # After 3 baseline requests
                await asyncio.sleep(1) # Simulate delay
                return None # Timeout or slow response
            return MagicMock(status_code=200, text="OK")

        with patch.object(ssrf_agent, 'make_request', side_effect=mock_time_request):
            with patch("agents.ssrf_agent.time.time") as mock_time:
                # Mock time to show 0.1 for baseline and 11.0 for slow
                mock_time.side_effect = [
                    100.0, 100.1, # baseline 1
                    100.2, 100.3, # baseline 2
                    100.4, 100.5, # baseline 3
                    110.0, 122.0  # slow target (12s)
                ]
                
                result = await ssrf_agent._test_blind_ssrf(
                    url="http://test.local/fetch",
                    method="GET",
                    params={"url": "http://example.com"},
                    param_name="url"
                )
                
                assert result is not None
                assert "blind" in result.description.lower()
                assert result.is_vulnerable is True

class TestSSRFCVSS:
    """Test CVSS scoring for SSRF."""

    def test_cloud_metadata_cvss(self, ssrf_agent):
        """Verify CVSS metrics for cloud metadata access."""
        from scoring.cvss_calculator import CVSSCalculator
        
        result = SSRFTestResult(
            is_vulnerable=True,
            payload="http://169.254.169.254/latest/meta-data/",
            description="Cloud Metadata Access: AWS",
            evidence="ami-id found",
            severity=Severity.CRITICAL,
            confidence=90,
            detection_method="ssrf_cloud"
        )
        
        ctx = ssrf_agent._build_ssrf_context(result, "http://test.local", "GET", "u")
        # Cloud metadata SSRF usually has high confidentiality impact and scope change
        assert ctx.can_access_cloud_metadata is True
        assert ctx.escapes_security_boundary is True
        
        calculator = CVSSCalculator()
        cvss_res = calculator.calculate(ctx)
        
        # Expect ~9.6-9.9 depending on specific metric determiners (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N or similar)
        # Actually I:N might be I:L if it can access internal services.
        assert cvss_res.score >= 8.0 # At least High
        assert cvss_res.severity in ["High", "Critical"]
