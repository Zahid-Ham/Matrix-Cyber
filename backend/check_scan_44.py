import asyncio
from sqlalchemy import select
from core.database import get_db_context
from models.scan import Scan

async def check_scan_44():
    async with get_db_context() as db:
        result = await db.execute(select(Scan).where(Scan.id == 44))
        scan = result.scalar_one_or_none()
        if scan:
            print(f"ID: {scan.id}")
            print(f"Target: {scan.target_url}")
            print(f"Files Count: {len(scan.scanned_files or [])}")
            print(f"Files: {scan.scanned_files}")
        else:
            print("Scan 44 not found")

if __name__ == "__main__":
    asyncio.run(check_scan_44())
