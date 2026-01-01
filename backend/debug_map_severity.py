
import sys
import os

# Add parent directory to path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, root_dir)

from agents.github_agent import GithubSecurityAgent

try:
    agent = GithubSecurityAgent()
    print("Agent initialized.")
    res = agent._map_severity("HIGH")
    print(f"Mapped 'HIGH' to: {res}")
    res = agent._map_severity(None)
    print(f"Mapped None to: {res}")
except Exception as e:
    print(f"CRASH: {e}")
    import traceback
    traceback.print_exc()
