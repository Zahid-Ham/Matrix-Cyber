import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select
import os
import json

# Relative import setup
import sys
sys.path.append(os.getcwd())

from backend.models.forensic import ForensicRecord, ForensicArtifact

DATABASE_URL = "postgresql+asyncpg://postgres:JSqgypVxpboadUmcgHxajWEWLZONvBbg@tramway.proxy.rlwy.net:17317/railway"

async def check_latest():
    engine = create_async_engine(DATABASE_URL)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with async_session() as session:
        # Get latest records
        result = await session.execute(
            select(ForensicRecord).order_by(ForensicRecord.created_at.desc()).limit(5)
        )
        records = result.scalars().all()
        
        for rec in records:
            print(f"Record: {rec.case_id} (Scan ID: {rec.scan_id})")
            art_res = await session.execute(
                select(ForensicArtifact).where(ForensicArtifact.scan_id == rec.scan_id)
            )
            arts = art_res.scalars().all()
            for art in arts:
                print(f"  - {art.name} ({art.artifact_type})")
            print("-" * 30)

if __name__ == "__main__":
    asyncio.run(check_latest())
