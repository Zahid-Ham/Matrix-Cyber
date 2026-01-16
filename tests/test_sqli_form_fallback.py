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
async def test_form_fallback():
    """
    Verify that SQLInjectionAgent tries both JSON and Form Data.
    """
    agent = SQLInjectionAgent()
    
    # Mock make_request to capture calls
    mock_request = AsyncMock()
    # Baseline existence check -> 200
    # Baseline POST -> 200 (Mock successful baseline)
    # Then payloads...
    mock_request.return_value = MagicMock(status_code=200, text="success")
    
    agent.make_request = mock_request
    
    # Run test
    with patch.object(SQLInjectionConfig, 'LOGIN_ENDPOINTS', ["/login"]):
        # Shorten payloads list for speed
        with patch.object(SQLInjectionConfig, 'JSON_LOGIN_PAYLOADS', [{"username": "test", "password": "test"}]):
             await agent._test_login_endpoints(
                target_url="http://test.com",
                scan_context=MagicMock(),
                detected_db="Unknown"
            )
            
    # Verify calls
    # Should see POST with json=... AND POST with data=...
    calls = mock_request.call_args_list
    
    print("\n--- Actual Calls ---")
    for c in calls:
        print(f"args={c.args}, kwargs={c.kwargs}")
        
    json_calls = [c for c in calls if 'json' in c.kwargs]
    
    def has_form_header(c):
        headers = c.kwargs.get('headers', {})
        # Case insensitive check
        return any(k.lower() == 'content-type' and v == 'application/x-www-form-urlencoded' for k, v in headers.items())

    form_calls = [c for c in calls if 'data' in c.kwargs and has_form_header(c)]
    
    assert len(json_calls) > 0, "Should have attempted JSON"
    assert len(form_calls) > 0, "Should have attempted Form Data"
    print("Agent successfully attempted both JSON and Form Data!")

if __name__ == "__main__":
    asyncio.run(test_form_fallback())
