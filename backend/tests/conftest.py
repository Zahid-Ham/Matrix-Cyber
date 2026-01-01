"""
Pytest Configuration and Shared Fixtures

Global fixtures for agent testing.
"""
import pytest
import json
from pathlib import Path
from typing import Dict, Any, List
from unittest.mock import Mock, AsyncMock

# Add backend to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from tests.fixtures.cvss_validators import *
from tests.fixtures.test_endpoints import *

# Configure pytest-asyncio to auto mode
pytest_plugins = ('pytest_asyncio',)


# ============================================================================
# TEST DATA FIXTURES
# ============================================================================

@pytest.fixture(scope="session")
def cvss_scenarios() -> Dict[str, Any]:
    """Load CVSS test scenarios from JSON."""
    scenarios_path = Path(__file__).parent / "test_data" / "cvss_scenarios.json"
    with open(scenarios_path, "r") as f:
        return json.load(f)


@pytest.fixture(scope="session")
def test_endpoints() -> Dict[str, List[Dict[str, Any]]]:
    """Get test endpoints for various scenarios."""
    return {
        "dvwa": DVWA_ENDPOINTS,
        "juice_shop": JUICE_SHOP_ENDPOINTS,
        "testphp": TESTPHP_ENDPOINTS,
        "safe": SAFE_ENDPOINTS,
        "mock": MOCK_VULNERABLE_ENDPOINTS
    }


# ============================================================================
# MOCK TARGET FIXTURES
# ============================================================================

@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    def _create_response(status_code=200, text="", headers=None):
        response = Mock()
        response.status_code = status_code
        response.text = text
        response.headers = headers or {}
        response.content = text.encode('utf-8')
        response.json = Mock(return_value={})
        return response
    return _create_response


@pytest.fixture
def mock_vulnerable_response(mock_response):
    """Create mock responses for vulnerable endpoints."""
    return {
        "sqli_error": mock_response(
            200,
            "You have an error in your SQL syntax near '1'' at line 1"
        ),
        "xss_reflected": mock_response(
            200,
            "<html><body>Search: <script>alert('XSS')</script></body></html>"
        ),
        "command_injection": mock_response(
            200,
            "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        ),
        "ssrf_metadata": mock_response(
            200,
            '{"code": "Success", "instanceId": "i-1234567890abcdef0"}'
        )
    }


# ============================================================================
# AGENT FIXTURES
# ============================================================================

@pytest.fixture
async def sql_agent():
    """Create SQL injection agent instance."""
    from agents.sql_injection_agent import SQLInjectionAgent
    agent = SQLInjectionAgent()
    yield agent
    await agent.close()


@pytest.fixture
async def xss_agent():
    """Create XSS agent instance."""
    from agents.xss_agent import XSSAgent
    # Disable caching to prevent cross-test pollution (global singleton cache)
    agent = XSSAgent(use_caching=False)
    yield agent
    await agent.close()


@pytest.fixture
async def command_injection_agent():
    """Create command injection agent instance."""
    from agents.command_injection_agent import CommandInjectionAgent
    agent = CommandInjectionAgent()
    yield agent
    await agent.close()


@pytest.fixture
async def csrf_agent():
    """Create CSRF agent instance."""
    from agents.csrf_agent import CSRFAgent
    agent = CSRFAgent()
    yield agent
    await agent.close()


# ============================================================================
# CVSS VALIDATION FIXTURES
# ============================================================================

@pytest.fixture
def cvss_validator():
    """Provide CVSS validation helper functions."""
    return {
        "validate_score": validate_cvss_score,
        "validate_vector": validate_cvss_vector,
        "validate_scope": validate_scope_change,
        "validate_pr": validate_privilege_required,
        "validate_ui": validate_user_interaction,
        "assert_metrics": assert_cvss_metrics
    }


# ============================================================================
# PYTEST MARKERS
# ============================================================================

def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "network: marks tests that require network access"
    )
    config.addinivalue_line(
        "markers", "benchmark: marks tests as performance benchmarks"
    )
    config.addinivalue_line(
        "markers", "cvss: marks tests for CVSS validation"
    )
