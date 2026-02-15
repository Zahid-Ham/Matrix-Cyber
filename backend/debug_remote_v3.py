import asyncio
import os
import ssl
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

DATABASE_URL = "postgresql+asyncpg://postgres:JSqgypVxpboadUmcgHxajWEWLZONvBbg@tramway.proxy.rlwy.net:17317/railway"

async def main():
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    print("--- DIAGNOSTIC V3: CUSTOM SSL CONTEXT ---")
    
    # Create a custom SSL context that ignores verification
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    print("Created relaxed SSL context.")

    try:
        # Pass the SSL context directly to asyncpg via connect_args
        engine = create_async_engine(
            DATABASE_URL,
            connect_args={"ssl": ctx}
        )
        print("Engine created. Attempting connection...")
        
        async with engine.connect() as conn:
            res = await conn.execute(text("SELECT version()"))
            print(f"✅ VICTORY! Connected to: {res.scalar()}")
    except Exception as e:
        print(f"❌ FAILED with custom context: {e}")

if __name__ == "__main__":
    asyncio.run(main())
