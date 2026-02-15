import sys
import os
sys.path.append(os.getcwd())

import asyncio
from sqlalchemy import select, cast, String
from core.database import async_session_maker as async_session_factory
from models.vulnerability import Vulnerability

async def clear_bad_intel():
    async with async_session_factory() as session:
        # Find XSS Reflected vulnerabilities
        query = select(Vulnerability).where(cast(Vulnerability.vulnerability_type, String).ilike('%XSS%'))
        result = await session.execute(query)
        vulns = result.scalars().all()
        
        print(f"Found {len(vulns)} XSS related vulnerabilities.")
        count = 0
        for v in vulns:
            if v.threat_intelligence:
                why = v.threat_intelligence.get('why_trending')
                print(f"ID: {v.id} | Why Trending: {why}")
                
                if why == "N/A" or why == "Analysis unavailable":
                    print(f" -> Clearing bad intelligence for ID {v.id}")
                    v.threat_intelligence = None
                    session.add(v)
                    count += 1
        
        if count > 0:
            await session.commit()
            print(f"Cleared intelligence for {count} vulnerabilities.")
        else:
            print("No bad intelligence found to clear.")

if __name__ == "__main__":
    asyncio.run(clear_bad_intel())
