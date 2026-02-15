import asyncio
from sqlalchemy import select
from core.database import get_db_context
from models.scan import Scan

async def check_playlistify():
    async with get_db_context() as db:
        result = await db.execute(select(Scan).where(Scan.target_url.like('%Playlistify%')))
        scans = result.scalars().all()
        for s in scans:
            print(f"ID: {s.id}, Target: {s.target_url}, Files: {len(s.scanned_files or [])}, Status: {s.status}")

if __name__ == "__main__":
    asyncio.run(check_playlistify())
