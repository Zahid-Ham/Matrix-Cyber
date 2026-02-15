import asyncio
import os
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

async def check_table():
    print(f"Connecting to: {DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else DATABASE_URL}...")
    engine = create_async_engine(DATABASE_URL)
    
    async with engine.connect() as conn:
        print("Fetching column details for 'scans' table...")
        stmt = text("""
            SELECT column_name, data_type, udt_name 
            FROM information_schema.columns 
            WHERE table_name = 'scans' AND column_name = 'scan_type'
        """)
        result = await conn.execute(stmt)
        row = result.fetchone()
        if row:
            print(f"Column: {row.column_name}, Type: {row.data_type}, UDT: {row.udt_name}")
        else:
            print("❌ Column 'scan_type' not found in 'scans' table.")

if __name__ == "__main__":
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(check_table())
