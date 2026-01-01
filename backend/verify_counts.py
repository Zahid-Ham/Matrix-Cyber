import asyncio
from sqlalchemy import select
from core.database import async_session_maker
from models.scan import Scan

async def verify_counts():
    async with async_session_maker() as db:
        # Get latest scan
        result = await db.execute(select(Scan).order_by(Scan.id.desc()).limit(1))
        scan = result.scalar_one_or_none()
        
        output = []
        if not scan:
            output.append("[-] No scans found.")
        else:
            output.append(f"[*] Latest Scan ID: {scan.id}")
            output.append(f"[*] Status: {scan.status}")
            output.append(f"[*] Total Vulns: {scan.total_vulnerabilities}")
            output.append(f"[*] Critical: {scan.critical_count}")
            output.append(f"[*] High: {scan.high_count}")
            output.append(f"[*] Medium: {scan.medium_count}")
            output.append(f"[*] Low: {scan.low_count}")
            output.append(f"[*] Info: {scan.info_count}")
            output.append(f"[*] Risk Score: {scan.risk_score}")
            output.append(f"[*] OWASP Coverage: {len(scan.owasp_coverage) if scan.owasp_coverage else 0}")
        
        with open("verification_result.txt", "w") as f:
            f.write("\n".join(output))

if __name__ == "__main__":
    asyncio.run(verify_counts())
