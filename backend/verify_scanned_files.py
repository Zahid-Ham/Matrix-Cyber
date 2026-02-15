import asyncio
from core.database import get_db_context, db_config
from models.scan import Scan
from sqlalchemy import select

async def check_latest_scan():
    async with get_db_context() as db:
        result = await db.execute(select(Scan).order_by(Scan.id.desc()))
        scan = result.scalars().first()
        if scan:
            print(f"Scan ID: {scan.id}")
            print(f"Status: {scan.status}")
            print(f"Scanned Files: {scan.scanned_files}")
            print(f"Raw Scanned Files (len): {len(scan.scanned_files) if scan.scanned_files else 0}")
        else:
            print("No scans found.")

if __name__ == "__main__":
    asyncio.run(check_latest_scan())
