import asyncio
from datetime import datetime, timezone
from sqlalchemy import select
from core.database import async_session_maker, engine
from models.vulnerability import Vulnerability, Severity, VulnerabilityType
from models.scan import Scan, ScanStatus

async def test_vuln_insertion():
    print("Testing Vulnerability insertion...")
    async with async_session_maker() as db:
        try:
            # Create a test scan
            scan = Scan(
                target_url="http://example.com",
                user_id=1,  # Assuming user 1 exists (after reset/registration)
                status=ScanStatus.RUNNING
            )
            db.add(scan)
            await db.flush()
            print(f"Created scan ID: {scan.id}")
            
            # Create a test vulnerability
            from models.vulnerability import VulnerabilityType, Severity
            vuln = Vulnerability(
                scan_id=scan.id,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                severity=Severity.HIGH,
                title="Test Vulnerability",
                description="Testing datetime consistency",
                url="http://example.com/vuln",
                detected_by="test_agent",
                detection_confidence=0.9
            )
            db.add(vuln)
            print("Vulnerability added to session. Committing...")
            await db.commit()
            print("Commit successful!")
            
        except Exception as e:
            print(f"Error during insertion: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            await db.rollback()

if __name__ == "__main__":
    asyncio.run(test_vuln_insertion())
