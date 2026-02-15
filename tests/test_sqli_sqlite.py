import pytest
import asyncio
import sys
import os
from unittest.mock import MagicMock, AsyncMock, patch

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Mock models before importing agent
sys.modules['backend.models.vulnerability'] = MagicMock()
sys.modules['backend.models'] = MagicMock()

from backend.agents.sql_injection_agent import SQLInjectionAgent, SQLInjectionConfig

@pytest.mark.asyncio
async def test_sqlite_payload_detection():
    """
    Verify that SQLInjectionAgent sends SQLite payloads and detects delay.
    """
    agent = SQLInjectionAgent()
    
    # Mock make_request to simulate delay for SQLite payload
    mock_request = AsyncMock()
    
    async def side_effect(*args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "success"
        
        # Check if it's the SQLite payload
        payload_val = ""
        if 'data' in kwargs:
             # It's a dict, get values
             payload_val = str(kwargs['data'].values())
        
        if "sqlite_master" in payload_val:
            # Simulate delay
            resp.elapsed.total_seconds.return_value = 6.0
        else:
            resp.elapsed.total_seconds.return_value = 0.1
            
        return resp

    mock_request.side_effect = side_effect
    agent.make_request = mock_request
    
    # Mock create_result to capture findings
    agent.create_result = MagicMock()
    agent.create_result.return_value = "VULN_FOUND"
    
    # Run test on login endpoint
    with patch.object(SQLInjectionConfig, 'LOGIN_ENDPOINTS', ["/login"]):
         # We want to ensure it iterates through payloads and finds the SQLite one
         await agent._test_login_endpoints(
            target_url="http://test.com",
            scan_context=MagicMock(),
            detected_db="Unknown" 
        )
            
    # Verify finding
    assert agent.create_result.called, "Should have detected vulnerability"
    
    # Verify arguments of create_result (should indicate SQL injection)
    call_args = agent.create_result.call_args
    assert "SQL_INJECTION" in str(call_args), "Should be SQL Injection type"
    print("Agent successfully detected SQLite time-based injection!")

if __name__ == "__main__":
    asyncio.run(test_sqlite_payload_detection())
