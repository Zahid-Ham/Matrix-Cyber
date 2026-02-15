import asyncio
import os
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

async def check_enum():
    print(f"Connecting to: {DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else DATABASE_URL}...")
    engine = create_async_engine(DATABASE_URL)
    
    async with engine.connect() as conn:
        print("Fetching enum values for 'scantype'...")
        # Postgres specific query to list enum values
        stmt = text("SELECT unnest(enum_range(NULL::scantype))")
        result = await conn.execute(stmt)
        values = result.scalars().all()
        print(f"Enum Values: {values}")
        
        if 'repo' in values:
            print("✅ 'repo' IS present.")
        else:
            print("❌ 'repo' is MISSING.")

if __name__ == "__main__":
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(check_enum())
