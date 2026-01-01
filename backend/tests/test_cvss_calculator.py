
import unittest
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scoring.cvss_calculator import CVSSCalculator
from scoring.vulnerability_context import VulnerabilityContext

class TestCVSSCalculator(unittest.TestCase):
    
    def setUp(self):
        self.calculator = CVSSCalculator()
    
    def test_sql_injection_error_based(self):
        """
        Test Case: Error-based SQL Injection (unauthenticated)
        CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8 (Critical)
        """
        context = VulnerabilityContext(
            vulnerability_type="sql_injection",
            detection_method="error_based",
            endpoint="/api/login",
            parameter="username",
            http_method="POST",
            requires_authentication=False,
            network_accessible=True,
            data_exposed=["database"],
            data_modifiable=["database"],
            requires_user_interaction=False,
            # SQLi typically doesn't change scope unless OS access confirmed, 
            # but context builder defaults to False unless specific indicators found
            escapes_security_boundary=False, 
            payload_succeeded=True
        )
        
        result = self.calculator.calculate(context)
        
        assert result.score >= 9.0
        assert "AV:N" in result.vector
        assert "PR:N" in result.vector
        assert "C:H" in result.vector
        assert "I:H" in result.vector
        
    def test_sql_injection_authenticated(self):
        """
        Test Case: SQL Injection requiring authentication
        CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H -> 8.8 (High)
        """
        context = VulnerabilityContext(
            vulnerability_type="sql_injection",
            detection_method="boolean_blind",
            endpoint="/admin/users",
            parameter="id",
            http_method="GET",
            requires_authentication=True,
            authentication_level="low",
            network_accessible=True,
            data_exposed=["database"],
            data_modifiable=["database"],
            requires_user_interaction=False,
            escapes_security_boundary=False,
            payload_succeeded=True
        )
        
        result = self.calculator.calculate(context)
        
        assert 8.0 <= result.score < 9.0
        assert "PR:L" in result.vector  # Requires Low privileges
        
    def test_reflected_xss(self):
        """
        Test Case: Reflected XSS
        CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N -> 6.1 (Medium)
        
        Reflected XSS:
        - AV:N (Network)
        - AC:L (Low)
        - PR:N (None)
        - UI:R (Required - victim must click link)
        - S:C (Changed - executes in browser context)
        - C:L (Low - access cookies/dom)
        - I:L (Low - modify page appearance)
        - A:N (None - usually doesn't crash browser/site)
        """
        context = VulnerabilityContext(
            vulnerability_type="xss_reflected",
            detection_method="reflection_analysis",
            endpoint="/search",
            parameter="q",
            http_method="GET",
            requires_authentication=False,
            network_accessible=True,
            data_exposed=["cookies", "dom_content"],
            data_modifiable=["dom_content"],
            # XSS requires user interaction
            requires_user_interaction=True,
            # XSS always changes scope (server -> browser)
            escapes_security_boundary=True,
            payload_succeeded=True
        )
        
        result = self.calculator.calculate(context)
        
        assert result.score >= 5.0 and result.score < 7.0
        assert "UI:R" in result.vector
        assert "S:C" in result.vector
        
    def test_stored_xss(self):
        """
        Test Case: Stored XSS
        Often higher impact or different privileges.
        """
        context = VulnerabilityContext(
            vulnerability_type="xss_stored",
            detection_method="stored_analysis",
            endpoint="/comments",
            parameter="body",
            http_method="POST",
            requires_authentication=True, # Posting usually requires auth
            authentication_level="low",
            network_accessible=True,
            data_exposed=["cookies", "dom_content"],
            data_modifiable=["dom_content"],
            requires_user_interaction=True, # Victim still needs to view
            escapes_security_boundary=True,
            payload_succeeded=True
        )
        
        result = self.calculator.calculate(context)
        
        assert "PR:L" in result.vector
        assert "S:C" in result.vector
        
    def test_command_injection(self):
        """
        Test Case: OS Command Injection
        CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H -> 10.0 (Critical)
        """
        context = VulnerabilityContext(
            vulnerability_type="command_injection",
            detection_method="time_delay",
            endpoint="/ping",
            parameter="ip",
            http_method="POST",
            requires_authentication=False,
            network_accessible=True,
            data_exposed=["system_files", "environment"],
            data_modifiable=["system_files"],
            service_disruption_possible=True, # Can crash server
            requires_user_interaction=False,
            escapes_security_boundary=True, # App -> OS
            payload_succeeded=True
        )
        
        result = self.calculator.calculate(context)
        
        assert result.score == 10.0
        assert "S:C" in result.vector
        
    def test_ssrf_internal(self):
        """
        Test Case: SSRF scanning internal ports
        CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N -> 5.8 (Medium) 
        OR depending on impact
        """
        context = VulnerabilityContext(
            vulnerability_type="ssrf",
            detection_method="connect_back",
            endpoint="/webhook",
            parameter="url",
            http_method="POST",
            requires_authentication=False,
            network_accessible=True,
            data_exposed=["internal_network"],
            data_modifiable=[],
            requires_user_interaction=False,
            escapes_security_boundary=True, # Web -> Internal Net
            payload_succeeded=True
        )
        
        result = self.calculator.calculate(context)
        
        assert "S:C" in result.vector
        assert result.metrics["AV"] == "N"

if __name__ == '__main__':
    unittest.main()
