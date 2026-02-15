import asyncio
from sqlalchemy.schema import CreateTable
from models.vulnerability import Vulnerability, Severity, VulnerabilityType
from core.database import async_session_maker, engine

async def test_validation():
    print("Testing Vulnerability model validation...")
    
    # Test 1: Capitalized string
    v1 = Vulnerability(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity="High", # Capitalized
        url="http://example.com",
        title="Test SQLi",
        description="Test description"
    )
    print(f"Severity 'High' -> {v1.severity}")
    
    # Test 2: Enum with value capitalization (if it existed, but let's test enum directly)
    v2 = Vulnerability(
        vulnerability_type="SQL_Injection", # Inconsistent case
        severity=Severity.CRITICAL,
        url="http://example.com",
        title="Test 2",
        description="Test 2"
    )
    print(f"Severity Severity.CRITICAL -> {v2.severity}")
    print(f"Type 'SQL_Injection' -> {v2.vulnerability_type}")

    if v1.severity == "high" and v2.vulnerability_type == "sql_injection":
        print("SUCCESS: Validation working correctly!")
    else:
        print(f"FAILURE: Validation failed. v1.severity={v1.severity}, v2.vulnerability_type={v2.vulnerability_type}")

if __name__ == "__main__":
    asyncio.run(test_validation())
