
import asyncio
import logging
import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agents.github_agent import GithubSecurityAgent
from core.logger import setup_logging

# Configure logging to stdout
setup_logging("INFO")
logger = logging.getLogger("test_agent")

async def test_scan():
    # Use a small public repo for testing
    target_url = "https://github.com/Viverun/Matrix" # Testing on itself
    
    # Initialize agent
    # It should pick up token from env/settings
    agent = GithubSecurityAgent()
    
    print("\n--- Starting Optimized GitHub Scan Test ---\n")
    
    results = await agent.scan(target_url)
    
    print("\n--- Scan Results ---\n")
    print(f"Total Finding: {len(results)}")
    for r in results:
        print(f"[{r.severity}] {r.vulnerability_type}: {r.title}")
    
    print("\n--- Agent Stats ---\n")
    for key, val in agent.stats.items():
        print(f"{key}: {val}")

if __name__ == "__main__":
    asyncio.run(test_scan())
