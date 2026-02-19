
import asyncio
import sys
import os

# Add backend directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select
from core.database import async_session_maker
from models import Vulnerability
from marketplace_simulation.services.marketplace_service import MarketplaceService

async def run_valuation():
    print("Starting Marketplace Valuation Backfill...")
    
    async with async_session_maker() as db:
        # Fetch all vulnerabilities
        result = await db.execute(select(Vulnerability))
        vulns = result.scalars().all()
        
        print(f"Found {len(vulns)} vulnerabilities to analyze.")
        
        count = 0
        for vuln in vulns:
            try:
                print(f"Analyzing: {vuln.title} (ID: {vuln.id})...")
                await MarketplaceService.analyze_vulnerability(vuln.id, db)
                count += 1
            except Exception as e:
                print(f"Failed to analyze vulnerability {vuln.id}: {e}")
        
        await db.commit()
        print(f"Successfully analyzed {count} vulnerabilities.")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(run_valuation())
