"""
Scanner Self-Security Tests - Phase 17 Validation.

Tests input validation, output sanitization, and internal security controls.
"""
import pytest
import html
import json
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.report_generator import ReportGenerator, ReportFormat, generate_report
from agents.base_agent import AgentResult
from models.vulnerability import Severity, VulnerabilityType


class TestOutputSanitization:
    """Test that scanner output is sanitized against injection attacks."""

    @pytest.fixture
    def malicious_result(self):
        """Create a result with malicious payloads in text fields."""
        result = MagicMock(spec=AgentResult)
        result.title = "Reflected XSS <script>alert(1)</script>"
        result.description = "Vulnerability with <b>HTML</b> injection"
        result.severity = Severity.HIGH
        result.vulnerability_type = VulnerabilityType.XSS_REFLECTED
        result.confidence = 90
        result.url = "http://example.com/search?q=<img src=x onerror=alert(1)>"
        result.parameter = "q"
        result.method = "GET"
        result.evidence = "Evidence with 'quote' and \"double quote\""
        result.remediation = "Fix using <safe> methods"
        result.owasp_category = "A03:2021-Injection"
        result.cwe_id = "CWE-79"
        result.agent_name = "XSSAgent"
        
        # Mock risk scoring
        result.likelihood = "High"
        result.impact = "Medium"
        result.exploitability_rationale = "Easy"
        
        # Mock request data
        result.request_data = {"payload": "<script>evil()</script>"}
        result.response_snippet = "Response contains <script>evil()</script>"
        result.ai_analysis = "AI says: Looks dangerous"
        result.remediation_code = "print('safe')"
        result.reference_links = ["http://evil.com"]
        
        return result

    def test_html_report_xss_protection(self, malicious_result):
        """HTML report should escape HTML entities in user-controlled fields."""
        generator = ReportGenerator()
        scan_metadata = {"target_url": "http://target.com", "duration": 1.0}
        
        report = generator.generate_report(
            [malicious_result], 
            scan_metadata, 
            ReportFormat.HTML
        )
        
        # Check that script tags are escaped
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report
        assert "<script>alert(1)</script>" not in report
        
        # Check URL encoding in display (optional, depending on implementation)
        # At minimum, it shouldn't execute if rendered
        assert "&lt;img src=x onerror=alert(1)&gt;" in report or "%3Cimg" in report
        assert "<img src=x onerror=alert(1)>" not in report

    def test_json_report_safe(self, malicious_result):
        """JSON report should be valid JSON and safe."""
        generator = ReportGenerator()
        scan_metadata = {"target_url": "http://target.com"}
        
        report = generator.generate_report(
            [malicious_result], 
            scan_metadata, 
            ReportFormat.JSON
        )
        
        data = json.loads(report)
        finding = data["findings"][0]
        
        # JSON handles its own escaping, verify it's intact
        assert finding["title"] == "Reflected XSS <script>alert(1)</script>"
        assert finding["evidence"]["proof_of_concept"]["payload"] == "<script>evil()</script>"


class TestInputValidation:
    """Test input validation for scanner targets."""

    def test_ssrf_prevention(self):
        """Scanner should not scan internal/loopback addresses unless allowed."""
        from scanner.target_analyzer import TargetAnalyzer
        
        # This test might need adjustment based on how I enforce this.
        # Ideally, we have a validator function.
        # For now, let's assume we create a validation utility in this phase.
        
        try:
            from core.input_validation import is_safe_url
            
            unsafe_urls = [
                "http://localhost",
                "http://127.0.0.1",
                "http://0.0.0.0",
                "http://169.254.169.254", # AWS metadata
                "file:///etc/passwd",
                "gopher://localhost:6379"
            ]
            
            for url in unsafe_urls:
                assert not is_safe_url(url), f"URL {url} should be rejected"
                
            safe_urls = [
                "http://example.com",
                "https://google.com",
                "http://1.1.1.1" # Public IP
            ]
            
            for url in safe_urls:
                assert is_safe_url(url), f"URL {url} should be accepted"
                
        except ImportError:
            pytest.ignore("Input validation module not yet created")


class TestPathTraversalPrevention:
    """Test preventing path traversal in file operations."""

    def test_report_path_traversal(self):
        """Should not be able to write reports outside intended directory."""
        from core.report_generator import generate_report
        
        results = []
        metadata = {}
        
        # Attempt to write to a location that might be sensitive or outside
        # Using a relative path that tries to go up
        unsafe_path = "../../../sensitive_file.txt"
        
        # This function relies on Path.mkdir(parents=True), but doesn't explicitly check bounds
        # We need to verify if it allows traversal or if we need to add a check
        
        # For the test, we'll assume we want to ENFORCE a check.
        # So we expect it to fail or be sanitized if we implement the fix.
        
        # If the code blindly writes, this test will actually create the file (bad for test env).
        # So we should mock the writing and check the path.
        
        with patch("pathlib.Path.write_text") as mock_write, \
             patch("pathlib.Path.mkdir"):
            
            # We want to ensure the resolved path starts with the artifacts/reports dir
            # But generate_report just takes a string.
            
            # Let's test a validation function we will implement
            try:
                from core.input_validation import validate_file_path
                
                with pytest.raises(ValueError):
                    validate_file_path(unsafe_path)
                    
            except ImportError:
                pytest.ignore("Input validation module not yet created")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
