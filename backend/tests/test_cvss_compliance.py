
import sys
import os
import unittest
from typing import Dict, Any

# Add parent directory to path to import backend modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scoring.vulnerability_context import VulnerabilityContext
from scoring.cvss_calculator import cvss_calculator
from scoring.metric_determiners import MetricDeterminers

class TestCVSSClaims(unittest.TestCase):

    def test_determinism(self):
        """Claim 1 & 2: CVSS calculation is 100% deterministic."""
        context = VulnerabilityContext(
            vulnerability_type="sqli",
            detection_method="error_based",
            endpoint="http://example.com/vuln",
            parameter="id",
            http_method="GET",
            requires_authentication=False,
            data_exposed=["database"]
        )
        
        # Run 100 times
        scores = [cvss_calculator.calculate(context).score for _ in range(100)]
        
        # All scores must be identical
        self.assertEqual(len(set(scores)), 1, "CVSS calculation is not deterministic")
        print(f"\n[PASS] Determinism: 100 iterations produced score {scores[0]}")

    def test_nvd_validation(self):
        """Claim 3: NVD Validation (3-5 cases)."""
        scenarios = [
            {
                "name": "CVE-2021-44228 (Log4Shell)",
                "nvd_score": 10.0,
                "context": VulnerabilityContext(
                    vulnerability_type="rce",
                    detection_method="exploit",
                    requires_authentication=False,
                    escapes_security_boundary=True, # RCE usually implies scope change if root/system obtained
                    can_execute_os_commands=True,
                    data_exposed=["all"], # RCE = Confidentiality High
                    data_modifiable=["all"], # RCE = Integrity High 
                    service_disruption_possible=True, # RCE = Availability High
                    additional_context={"dos_severity": "complete"}
                )
            },
            {
                "name": "CVE-2017-5638 (Struts2 RCE)",
                "nvd_score": 10.0,
                "context": VulnerabilityContext(
                    vulnerability_type="rce",
                    detection_method="exploit",
                    requires_authentication=False,
                    escapes_security_boundary=True,
                    can_execute_os_commands=True,
                    data_exposed=["all"],
                    data_modifiable=["all"],
                    service_disruption_possible=True,
                    additional_context={"dos_severity": "complete"}
                )
            },
            {
                "name": "CVE-2014-0160 (Heartbleed)",
                "nvd_score": 7.5, # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
                "context": VulnerabilityContext(
                    vulnerability_type="info_disclosure",
                    detection_method="exploit",
                    requires_authentication=False,
                    escapes_security_boundary=False, # It's memory read, usually S:U in CVSS 3.0/3.1 check
                    data_exposed=["keys", "passwords", "pii"], # High confidentiality
                    data_modifiable=[],
                    service_disruption_possible=False
                )
            }
        ]

        print("\n[TEST] NVD Validation:")
        for s in scenarios:
            result = cvss_calculator.calculate(s["context"])
            print(f"  - {s['name']}: Calculated {result.score} vs NVD {s['nvd_score']}")
            self.assertAlmostEqual(result.score, s["nvd_score"], delta=0.5)

    def test_scope_logic(self):
        """Concern 1: Scope Determination Logic."""
        
        # 1. SQLi DB only -> U
        ctx1 = VulnerabilityContext(vulnerability_type="sqli", data_exposed=["database"], escapes_security_boundary=False)
        self.assertEqual(MetricDeterminers.determine_scope(ctx1), "U", "SQLi (DB only) should be S:U")
        
        # 2. SQLi xp_cmdshell -> C
        ctx2 = VulnerabilityContext(vulnerability_type="sqli", can_execute_os_commands=True, escapes_security_boundary=True)
        self.assertEqual(MetricDeterminers.determine_scope(ctx2), "C", "SQLi (xp_cmdshell) should be S:C")

        # 3. SSRF Internal IP -> U or C?
        # Note: CVSS spec says accessing internal service via SSRF is typically S:C 
        # But user asked: "SSRF to 192.168.1.1 | U (Unchanged) | ?" vs "169.254... | C"
        # My code currently sets C if "can_access_internal_network" is True.
        # Let's verify what it does.
        ctx3 = VulnerabilityContext(vulnerability_type="ssrf", can_access_internal_network=True)
        # Note: If I strictly follow user's table, they imply strict differentiation. 
        # But strictly standard: SSRF allowing interaction with component not managed by same authority = C.
        # Internal network is usually NOT managed by web app authority.
        # Let's see what my code produces.
        scope3 = MetricDeterminers.determine_scope(ctx3)
        print(f"\n[INFO] SSRF Internal Scope: {scope3}")

        # 4. SSRF Metadata -> C
        ctx4 = VulnerabilityContext(vulnerability_type="ssrf", can_access_cloud_metadata=True)
        self.assertEqual(MetricDeterminers.determine_scope(ctx4), "C", "SSRF Metadata should be S:C")

    def test_attack_complexity(self):
        """Concern 2: Attack Complexity."""
        
        # 1. Time-based SQLi -> L (per User request "Should be L")
        ctx1 = VulnerabilityContext(vulnerability_type="sqli", detection_method="time_blind")
        # Time blind might be considered "specific conditions" by some, but usually AC:L for automation.
        ac1 = MetricDeterminers.determine_attack_complexity(ctx1)
        self.assertEqual(ac1, "L", "Time-based SQLi should be AC:L")

        # 2. WAF evasion -> H
        ctx2 = VulnerabilityContext(vulnerability_type="xss", behind_waf=True, security_controls_bypassed=["waf"])
        ac2 = MetricDeterminers.determine_attack_complexity(ctx2)
        self.assertEqual(ac2, "H", "WAF evasion should be AC:H")

if __name__ == "__main__":
    unittest.main()
