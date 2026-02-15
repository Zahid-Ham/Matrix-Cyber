import asyncio
from sqlalchemy import text
from core.database import get_engine

async def add_scanned_files_column():
    engine = get_engine()
    async with engine.begin() as conn:
        try:
            # Check if column exists first (Postgres specific)
            result = await conn.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='scans' AND column_name='scanned_files';
            """))
            if not result.fetchone():
                print("Adding 'scanned_files' column to 'scans' table...")
                await conn.execute(text("ALTER TABLE scans ADD COLUMN scanned_files JSON DEFAULT '[]'::json;"))
                print("Column added successfully.")
            else:
                print("Column 'scanned_files' already exists.")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(add_scanned_files_column())
