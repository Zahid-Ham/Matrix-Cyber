import asyncio
from datetime import datetime, timezone
from models.vulnerability import Vulnerability, Severity, VulnerabilityType

def test_vuln_instantiation():
    try:
        print("[*] Testing Vulnerability instantiation...")
        v = Vulnerability(
            scan_id=1,
            title="Test Title",
            description="Test Description",
            severity=Severity.HIGH,
            vulnerability_type=VulnerabilityType.XSS_REFLECTED,
            url="http://example.com",
            parameter="q",
            method="GET",
            evidence="alert(1)",
            remediation="Fix it",
            remediation_code="code",
            ai_analysis="{}",
            owasp_category="A03:2021",
            cwe_id="CWE-79",
            detected_at=datetime.now(timezone.utc),
            cvss_score=8.5,
            cvss_vector="CVSS:3.1/...",
            likelihood=5.0,
            impact=5.0,
            exploit_confidence=90.0,
            detection_confidence=95.0,
            scope_impact={}
        )
        print("[*] Calling auto_map_owasp_cwe()...")
        v.auto_map_owasp_cwe()
        print("[+] Method call successful!")
        print("[+] Instantiation successful!")
    except Exception as e:
        print(f"[-] Instantiation failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_vuln_instantiation()
