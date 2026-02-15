import asyncio
import os
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

# Remote URL from .env
DATABASE_URL = "postgresql+asyncpg://postgres:JSqgypVxpboadUmcgHxajWEWLZONvBbg@tramway.proxy.rlwy.net:17317/railway"

# SSL Modes to test
SSL_MODES = ["disable", "prefer", "require"]

async def test_mode(mode):
    url_with_ssl = f"{DATABASE_URL}?ssl={mode}"
    print(f"\n--- Testing SSL Mode: {mode} ---")
    print(f"URL: {url_with_ssl.replace('JSqgypVxpboadUmcgHxajWEWLZONvBbg', '***')}")
    
    try:
        # Create engine with specific connect args for asyncpg to be permissive if needed
        engine = create_async_engine(url_with_ssl)
        
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT version()"))
            version = result.scalar()
            print(f"✅ SUCCESS! Connected to: {version}")
            return True
    except Exception as e:
        print(f"❌ FAILED: {str(e).split('newline')[0]}...")
        return False

async def main():
    print("Starting Remote Database Connection Diagnostics...")
    
    # Standard test
    for mode in SSL_MODES:
        if await test_mode(mode):
            print(f"\nRecommended Configuration: Add ?ssl={mode} to DATABASE_URL")
            break
    else:
        print("\nAll standard SSL modes failed. Please check network/firewall settings.")

if __name__ == "__main__":
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
