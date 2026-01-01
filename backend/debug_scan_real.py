import asyncio
import os
import sys

# Add backend to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agents.github_agent import GithubSecurityAgent
from core.logger import setup_logging
import logging

# Setup logging to console and file
setup_logging(level="DEBUG")
logger = logging.getLogger(__name__)
fh = logging.FileHandler('debug_output.txt', mode='w', encoding='utf-8')
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(name)s | %(message)s')
fh.setFormatter(formatter)
logging.getLogger().addHandler(fh)

async def run_debug_scan():
    try:
        from config import get_settings
        settings = get_settings()
        
        url = "https://github.com/appsecco/dvna"
        logger.info(f"Starting debug scan for {url}")
        
        agent = GithubSecurityAgent(github_token=settings.github_token)
        results = await agent.scan(
            target_url=url
        )
        
        print(f"\nScan Complete. Found {len(results)} vulnerabilities.")
        for res in results:
            print(f"[{res.severity}] {res.title}")
            
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)

if __name__ == "__main__":
    asyncio.run(run_debug_scan())
