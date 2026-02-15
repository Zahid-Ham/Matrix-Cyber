import asyncio
import os
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

async def check_latest_scan():
    print(f"Connecting to: {DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else DATABASE_URL}...")
    engine = create_async_engine(DATABASE_URL)
    
    async with engine.connect() as conn:
        print("Fetching latest scan...")
        stmt = text("""
            SELECT id, status, total_vulnerabilities, critical_count, high_count, medium_count, low_count, info_count, scan_type
            FROM scans 
            ORDER BY id DESC 
            LIMIT 1
        """)
        result = await conn.execute(stmt)
        scan = result.fetchone()
        
        if scan:
            print(f"Latest Scan ID: {scan.id}")
            print(f"Status: {scan.status}")
            print(f"Type: {scan.scan_type}")
            print(f"Total Issues: {scan.total_vulnerabilities}")
            print(f"Critical: {scan.critical_count}")
            print(f"High: {scan.high_count}")
            print(f"Medium: {scan.medium_count}")
            print(f"Low: {scan.low_count}")
            print(f"Info: {scan.info_count}")
        else:
            print("❌ No scans found.")

if __name__ == "__main__":
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(check_latest_scan())
