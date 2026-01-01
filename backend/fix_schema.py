import asyncio
from sqlalchemy import text
from core.database import db_config

async def fix_schema():
    print("Fixing database schema (SQLite)...")
    async with db_config.engine.begin() as conn:
        # Check columns in 'users' table using PRAGMA
        result = await conn.execute(text("PRAGMA table_info(users)"))
        columns = [row[1] for row in result.fetchall()]
        
        if 'company' not in columns:
            print("Adding 'company' column to 'users' table...")
            await conn.execute(text("ALTER TABLE users ADD COLUMN company VARCHAR(255)"))
            print("'company' column added.")
        else:
            print("'company' column already exists.")

if __name__ == "__main__":
    asyncio.run(fix_schema())
