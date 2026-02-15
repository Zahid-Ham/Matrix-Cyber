import sys
import os
sys.path.append(os.getcwd())

import asyncio
from sqlalchemy import select, cast, String
from core.database import async_session_maker as async_session_factory
from models.vulnerability import Vulnerability

async def check_vulns():
    async with async_session_factory() as session:
        # Find XSS Reflected vulnerabilities
        query = select(Vulnerability).where(cast(Vulnerability.vulnerability_type, String).ilike('%XSS%'))
        result = await session.execute(query)
        vulns = result.scalars().all()
        
        print(f"Found {len(vulns)} XSS related vulnerabilities.")
        for v in vulns:
            print(f"ID: {v.id}")
            print(f"Type: {v.vulnerability_type}")
            print(f"Has Intelligence: {bool(v.threat_intelligence)}")
            if v.threat_intelligence:
                print(f"Intelligence Keys: {list(v.threat_intelligence.keys())}")
                print(f"Why Trending: {v.threat_intelligence.get('why_trending')}")
                print(f"Attack Summary: {v.threat_intelligence.get('attack_summary')}")
                print(f"Real World Exploit Flow: {v.threat_intelligence.get('real_world_exploit_flow')}")
            print("-" * 50)

    # Test Groq Connection
    print("\nTesting Groq API Connection...")
    try:
        from config import get_settings
        import httpx
        import json
        
        settings = get_settings()
        api_key = settings.groq_api_key_scanner
        print(f"Using API Key: {api_key[:10]}...")
        
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": settings.groq_model_scanner_primary,
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 10
        }
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, headers=headers, json=payload)
            print(f"Groq Response Status: {resp.status_code}")
            if resp.status_code != 200:
                print(f"Groq Error: {resp.text}")
            else:
                print("Groq Connection Successful!")
                
    except Exception as e:
        print(f"Groq Test Failed: {e}")

if __name__ == "__main__":
    asyncio.run(check_vulns())
