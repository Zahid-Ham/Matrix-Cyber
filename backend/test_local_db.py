import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
import os

# Default local connection string from config.py
DATABASE_URL = "postgresql+asyncpg://matrix:matrix_secure_pass@localhost:5432/matrix"

async def test_connection():
    print(f"Testing connection to {DATABASE_URL}...")
    try:
        engine = create_async_engine(DATABASE_URL)
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            print(f"Connection successful: {result.scalar()}")
        print("Done.")
    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_connection())
