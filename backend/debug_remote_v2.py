import asyncio
import os
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

DATABASE_URL = "postgresql+asyncpg://postgres:JSqgypVxpboadUmcgHxajWEWLZONvBbg@tramway.proxy.rlwy.net:17317/railway"

# Only test disable and prefer, require failed
SSL_MODES = ["disable", "prefer"]

async def main():
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    print("--- DIAGNOSTIC START ---")
    for mode in SSL_MODES:
        url = f"{DATABASE_URL}?ssl={mode}"
        print(f"\nTrying mode: {mode}")
        try:
            engine = create_async_engine(url)
            async with engine.connect() as conn:
                res = await conn.execute(text("SELECT version()"))
                print(f"SUCCESS with {mode}: {res.scalar()}")
                return
        except Exception as e:
            print(f"FAILED with {mode}: {e}")
    print("\nAll attempts failed.")

if __name__ == "__main__":
    asyncio.run(main())
