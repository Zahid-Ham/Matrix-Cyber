"""
Command Injection Agent Unit Tests

Comprehensive tests for OS Command Injection detection logic.
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from agents.command_injection_agent import CommandInjectionAgent, InjectionContext

# Use our custom markers
pytestmark = [pytest.mark.asyncio, pytest.mark.unit]


class TestCommandInjectionDetection:
    """Test detection of OS Command Injection vulnerabilities."""

    @pytest.mark.asyncio
    async def test_error_based_detection_unix(self, command_injection_agent, mock_response):
        """
        Verify detection of Unix command injection (e.g., | id).
        """
        # Scenario:
        # Agent sends "| id"
        # Server reflects "uid=1000(user) gid=1000(user)"
        # This matches UID_PATTERN (Strong) and indicators "uid=", "gid="
        
        target_url = "http://test.local/exec"
        endpoints = [{"url": target_url, "params": {"cmd": "test"}}]
        
        # Mock behavior
        async def mock_request_side_effect(url, method, params=None, **kwargs):
            cmd_val = params.get("cmd", "") if params else ""
            
            # If payload is "| id" (or similar), return vulnerable output
            if "id" in cmd_val:
                return mock_response(
                    200, 
                    "uid=1000(www-data) gid=1000(www-data) groups=1000(www-data)"
                )
            
            return mock_response(200, "Normal output")

        with patch.object(command_injection_agent.http_client, 'request', side_effect=mock_request_side_effect):
             # Mock AI analysis
            with patch.object(command_injection_agent, 'analyze_with_ai', new_callable=AsyncMock) as mock_ai:
                mock_ai.return_value = {
                    "is_vulnerable": True,
                    "confidence": 95.0,
                    "reason": "Command output confirmed"
                }

                results = await command_injection_agent.scan(
                    "http://test.local", 
                    endpoints
                )
                
                assert len(results) > 0
                finding = results[0]
                assert finding.is_vulnerable == True
                assert finding.severity.value == "critical"
                assert "OS Command Injection" in finding.title
                assert "uid=1000" in finding.response_snippet

    @pytest.mark.asyncio
    async def test_error_based_detection_windows(self, command_injection_agent, mock_response):
        """
        Verify detection of Windows command injection (e.g., & dir).
        """
        # Scenario:
        # Agent sends "& dir"
        # Server reflects Windows dir output
        
        target_url = "http://test.local/exec"
        endpoints = [{"url": target_url, "params": {"cmd": "test"}}]
        
        # Mock behavior
        async def mock_request_side_effect(url, method, params=None, **kwargs):
            cmd_val = params.get("cmd", "") if params else ""
            
            # If payload is "& dir"
            if "dir" in cmd_val or "type" in cmd_val:
                return mock_response(
                    200, 
                    " Volume in drive C has no label.\n Directory of C:\\Windows\n\n12/31/2025  12:00 PM <DIR> ."
                )
            
            return mock_response(200, "Normal output")

        # Force Windows detection 
        with patch.object(command_injection_agent, '_detect_windows_target', return_value=True):
            with patch.object(command_injection_agent.http_client, 'request', side_effect=mock_request_side_effect):
                 # Mock AI analysis
                with patch.object(command_injection_agent, 'analyze_with_ai', new_callable=AsyncMock) as mock_ai:
                    mock_ai.return_value = {
                        "is_vulnerable": True,
                        "confidence": 95.0,
                        "reason": "Windows command output confirmed"
                    }

                    results = await command_injection_agent.scan(
                        "http://test.local", 
                        endpoints,
                        technology_stack=["IIS", "ASP.NET"]
                    )
                    
                    assert len(results) > 0
                    finding = results[0]
                    assert finding.is_vulnerable == True
                    assert "OS Command Injection" in finding.title
                    assert "Directory of" in finding.response_snippet

    @pytest.mark.asyncio
    async def test_time_based_detection(self, command_injection_agent, mock_response):
        """
        Verify time-based blind command injection detection.
        """
        # Should initiate if error-based fails
        endpoints = [{"url": "http://test.local/exec", "params": {"cmd": "test"}}]
        
        # Mock responses
        fast_resp = mock_response(200, "Normal")
        
        # We need to control the timing of the request using side_effect
        # _make_safe_request calls make_request -> http_client.request
        
        # To make it deterministic without actually sleeping:
        # 1. Mock _measure_baseline_timing to return a fixed baseline
        # 2. Mock _test_single_timing to return True for expected payloads
        
        # Or, we can mock `make_request` to sleep for specific payloads.
        # But real sleep makes tests slow.
        # Creating a custom side effect with asyncio.sleep is better if we patch sleep or keep it small.
        # But AgentConfig uses 3, 5, 7 seconds. That's too long.
        
        # Strategy: Patch Config to use very small delays, and mock sleep in make_request
        
        # Disable caching to prevent interference from other tests (singleton cache)
        command_injection_agent.use_caching = False
        
        # Strategy: Patch Config to use very small delays, and mock sleep in make_request
        with patch("agents.command_injection_agent.CommandInjectionConfig.TIME_DELAYS", [0.1, 0.2]):
            with patch("agents.command_injection_agent.CommandInjectionConfig.BASELINE_SAMPLES", 2):
                with patch("agents.command_injection_agent.CommandInjectionConfig.TIMING_TOLERANCE", 0.05):
                    with patch("agents.command_injection_agent.CommandInjectionConfig.MIN_CONFIRMATIONS", 1):
                        
                        # Mock AI analysis
                        with patch.object(command_injection_agent, 'analyze_with_ai', new_callable=AsyncMock) as mock_ai:
                            mock_ai.return_value = {
                                "is_vulnerable": True,
                                "confidence": 95.0,
                                "reason": "Time-based injection confirmed"
                            }
                        
                            # Signature for httpx.AsyncClient.request is (method, url, ...)
                            async def mock_timed_request(method, url, **kwargs):
                                params = kwargs.get("params", {})
                                data = kwargs.get("data", {})
                                
                                # Check params or data for payload
                                cmd_val = ""
                                if params and isinstance(params, dict):
                                    cmd_val = params.get("cmd", "")
                                if data and isinstance(data, dict):
                                    cmd_val = data.get("cmd", "")
                                
                                cmd_val = str(cmd_val)

                                # Baseline requests (no sleep payload)
                                if "sleep" not in cmd_val:
                                    return fast_resp
                                
                                # Payload requests: extract delay AND simulate it
                                if "0.1" in cmd_val:
                                    await asyncio.sleep(0.12) # Within 0.1 +/- 0.05
                                elif "0.2" in cmd_val:
                                    await asyncio.sleep(0.22) # Within 0.2 +/- 0.05
                                
                                return fast_resp

                            # Patch http_client.request specifically
                            with patch.object(command_injection_agent.http_client, 'request', side_effect=mock_timed_request):
                                results = await command_injection_agent.scan(
                                    "http://test.local", 
                                    endpoints
                                )
                                
                                assert len(results) > 0
                                
                                finding = results[0]
                                assert finding.is_vulnerable == True
                                assert "Time-based" in finding.title
                                assert "Blind Command Injection" in finding.title


    @pytest.mark.asyncio
    async def test_false_positive_filtering(self, command_injection_agent, mock_response):
        """
        Verify that responses with error keywords are filtered even if they contain indicators.
        """
        endpoints = [{"url": "http://test.local/search", "params": {"q": "test"}}]
        
        # Response contains "root" but also "error" (e.g., "Syntax error near root")
        error_resp = mock_response(200, "Syntax error: Unexpected token 'root' at line 1")
        
        async def mock_request_side_effect(*args, **kwargs):
            return error_resp
            
        with patch.object(command_injection_agent.http_client, 'request', side_effect=mock_request_side_effect):
             results = await command_injection_agent.scan(
                "http://test.local", 
                endpoints
             )
             
             # Should be filtered out by _verify_command_output due to error keyword
             assert len(results) == 0


class TestCommandInjectionCVSS:
    """Validate CVSS scoring for Command Injection."""

    @pytest.mark.asyncio
    async def test_authenticated_cmd_injection_cvss(self, command_injection_agent):
        """Validate 9.9 score for authenticated Command Injection."""
        # Manually build context to test the calculator logic within the agent's context
        context = command_injection_agent._build_command_injection_context(
            url="http://test.local/exec",
            method="POST",
            param_name="cmd",
            payload="; id",
            description="Direct injection"
        )
        # Set authentication to LOW
        context.requires_authentication = True
        context.authentication_level = "low"
        
        result = command_injection_agent.cvss_calculator.calculate(context)
        # CVSS 3.1: AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H => 9.9
        assert result.score == 9.9
        assert result.vector.startswith("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")

    @pytest.mark.asyncio
    async def test_admin_cmd_injection_cvss(self, command_injection_agent):
        """Validate 9.1 score for admin-only Command Injection."""
        context = command_injection_agent._build_command_injection_context(
            url="http://test.local/admin/exec",
            method="POST",
            param_name="cmd",
            payload="; id",
            description="Admin-only direct injection"
        )
        # Set authentication to HIGH
        context.requires_authentication = True
        context.authentication_level = "high"
        
        result = command_injection_agent.cvss_calculator.calculate(context)
        # CVSS 3.1: AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H => 9.1
        assert result.score == 9.1
        assert result.vector.startswith("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H")
