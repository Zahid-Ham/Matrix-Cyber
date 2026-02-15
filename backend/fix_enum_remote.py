import asyncio
import os
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

async def fix_enum():
    print(f"Connecting to: {DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else DATABASE_URL}...")
    
    engine = create_async_engine(DATABASE_URL, isolation_level="AUTOCOMMIT")
    
    async with engine.connect() as conn:
        try:
            print("Attempting to add 'repo' to 'scantype' enum...")
            
            # PostgreSQL command to add value to enum (if not exists)
            # wrapped in DO block
            await conn.execute(text("""
                DO $$
                BEGIN
                    ALTER TYPE scantype ADD VALUE 'repo';
                EXCEPTION
                    WHEN duplicate_object THEN null;
                END $$;
            """))
            print("✅ Successfully added 'repo' to enum.")
            
        except Exception as e:
            print(f"❌ ERROR: {e}")
            
    # Verify in a new connection/session
    print("Verifying change...")
    async with engine.connect() as conn:
         result = await conn.execute(text("SELECT enum_range(NULL::scantype)"))
         print(f"Current Enum Values: {result.scalar()}")

if __name__ == "__main__":
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(fix_enum())
