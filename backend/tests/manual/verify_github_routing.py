
import asyncio
import os
import sys

# Add parent directory to path (Matrix root)
root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, root_dir)
# Add backend directory to path (for 'core' imports)
sys.path.insert(0, os.path.join(root_dir, 'backend'))

from backend.agents.orchestrator import AgentOrchestrator, AgentNames

async def test_routing():
    print("Testing Agent Orchestrator Routing Logic...")
    
    orchestrator = AgentOrchestrator()
    
    # Test Case 1: GitHub URL with no specific agents enabled (default)
    target_github = "https://github.com/test/repo"
    agents = orchestrator._select_agents(target_github, agents_enabled=None)
    print(f"\nTarget: {target_github}")
    print(f"Agents Enabled: None (Auto)")
    print(f"Selected Agents: {agents}")
    
    if agents == [AgentNames.GITHUB]:
        print("PASS: Correctly selected only GitHub agent.")
    else:
        print(f"FAIL: Expected {[AgentNames.GITHUB]}, got {agents}")
        
    # Test Case 2: GitHub URL with explicit DAST agents requested (should be ignored/overridden)
    target_github = "https://github.com/test/repo"
    agents_requested = [AgentNames.SQL_INJECTION, AgentNames.XSS]
    agents = orchestrator._select_agents(target_github, agents_enabled=agents_requested)
    print(f"\nTarget: {target_github}")
    print(f"Agents Requested: {agents_requested}")
    print(f"Selected Agents: {agents}")
    
    if agents == [AgentNames.GITHUB]:
        print("PASS: Correctly forced GitHub agent despite request.")
    else:
        print(f"FAIL: Expected {[AgentNames.GITHUB]}, got {agents}")

    # Test Case 3: Standard Web URL (Standard DAST)
    target_web = "https://example.com"
    agents = orchestrator._select_agents(target_web, agents_enabled=None)
    print(f"\nTarget: {target_web}")
    print(f"Agents Enabled: None (Auto)")
    print(f"Selected Agents: {agents}")
    
    if AgentNames.GITHUB not in agents and len(agents) > 1:
        print("PASS: Selected multiple DAST agents (no GitHub).")
    else:
        print(f"FAIL: Expected multiple DAST agents, got {agents}")

if __name__ == "__main__":
    asyncio.run(test_routing())
