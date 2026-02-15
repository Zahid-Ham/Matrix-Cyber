import asyncio
import json
import os
import sys

# sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.threat_intelligence_service import threat_intel_service
from models.vulnerability import VulnerabilityType, Severity
from datetime import datetime, timezone

class MockVuln:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

async def test_intel_service():
    print("=== Testing Threat Intelligence Service ===")
    
    # 1. Test NVD Fetch
    print("\n[1] Testing NVD Fetch...")
    nvd_data = await threat_intel_service.fetch_nvd_data()
    print(f"Fetched {len(nvd_data.get('vulnerabilities', []))} vulnerabilities from NVD.")
    
    # 2. Test CISA Fetch
    print("\n[2] Testing CISA Fetch...")
    cisa_data = await threat_intel_service.fetch_cisa_data()
    print(f"Fetched {len(cisa_data.get('vulnerabilities', []))} exploited vulnerabilities from CISA.")
    
    # 3. Test Trend Score Calculation
    print("\n[3] Testing Trend Score Calculation for SQL Injection...")
    score_data = threat_intel_service.compute_trend_score(
        VulnerabilityType.SQL_INJECTION, 
        nvd_data, 
        cisa_data
    )
    print(json.dumps(score_data, indent=2))
    
    # 4. Test AI Analysis (Mock Vuln)
    print("\n[4] Testing AI Analysis (Groq)...")
    mock_vuln = MockVuln(
        id=999,
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        title="SQL Injection in login.php",
        evidence="SELECT * FROM users WHERE username = '" + "admin' OR '1'='1" + "'",
        severity=Severity.CRITICAL,
        scan_id=1,
        detected_at=datetime.now(timezone.utc),
        threat_intelligence=None
    )
    
    try:
        intel = await threat_intel_service.get_threat_intelligence(mock_vuln)
        print("AI Analysis Result:")
        print(json.dumps(intel, indent=2))
    except Exception as e:
        print(f"AI Analysis failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_intel_service())
