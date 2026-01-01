import asyncio
import os
from sqlalchemy import select
from core.database import async_session_maker
from models.scan import Scan

async def list_scans():
    async with async_session_maker() as db:
        result = await db.execute(select(Scan).order_by(Scan.id.desc()).limit(10))
        scans = result.scalars().all()
        filepath = os.path.join(os.getcwd(), "scans_audit.txt")
        print(f"Writing to {filepath}")
        with open(filepath, "w") as f:
            for s in scans:
                f.write(f"ID: {s.id} | Target: {s.target_url} | Status: {s.status} | Vulnerabilities: {s.total_vulnerabilities} | Error: {s.error_message}\n")

if __name__ == "__main__":
    asyncio.run(list_scans())
