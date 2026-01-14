import asyncio
from sqlalchemy import select
from models.scan import Scan
from core.database import async_session_maker

async def check_scan_48():
    async with async_session_maker() as session:
        result = await session.execute(select(Scan).where(Scan.id == 48))
        scan = result.scalar_one_or_none()
        
        if scan:
            print(f"Scan 48 Found:")
            print(f"  Target: {scan.target_url}")
            print(f"  Status: {scan.status}")
            print(f"  Progress: {scan.progress}%")
            print(f"  Scan Type: {scan.scan_type}")
            print(f"  Created: {scan.created_at}")
            print(f"  Updated: {scan.updated_at}")
            print(f"  Error: {scan.error_message}")
        else:
            print("Scan 48 not found in database")

if __name__ == "__main__":
    asyncio.run(check_scan_48())
