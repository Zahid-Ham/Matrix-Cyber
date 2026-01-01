
import os
import sys

# Add parent directory to path (Matrix root)
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, root_dir)
sys.path.insert(0, os.path.join(root_dir, 'backend'))

print("Attempting to import GithubSecurityAgent...")
try:
    from backend.agents.github_agent import GithubSecurityAgent
    print("Import SUCCESS")
except Exception as e:
    print(f"Import FAILED: {e}")
