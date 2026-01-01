"""
Test Endpoint Fixtures

Known vulnerable and safe endpoints for testing agents.
"""
from typing import List, Dict, Any


# ============================================================================
# VULNERABLE TEST ENDPOINTS
# ============================================================================

DVWA_ENDPOINTS: List[Dict[str, Any]] = [
    {
        "name": "DVWA SQL Injection",
        "url": "http://localhost/dvwa/vulnerabilities/sqli/",
        "method": "GET",
        "params": {"id": "1", "Submit": "Submit"},
        "expected_vulns": ["sql_injection"],
        "difficulty": "low"
    },
    {
        "name": "DVWA XSS Reflected",
        "url": "http://localhost/dvwa/vulnerabilities/xss_r/",
        "method": "GET",
        "params": {"name": "test"},
        "expected_vulns": ["xss"],
        "difficulty": "low"
    },
    {
        "name": "DVWA Command Injection",
        "url": "http://localhost/dvwa/vulnerabilities/exec/",
        "method": "POST",
        "params": {"ip": "127.0.0.1", "Submit": "Submit"},
        "expected_vulns": ["command_injection"],
        "difficulty": "low"
    }
]

JUICE_SHOP_ENDPOINTS: List[Dict[str, Any]] = [
    {
        "name": "Juice Shop SQL Injection",
        "url": "http://localhost:3000/rest/products/search",
        "method": "GET",
        "params": {"q": "test"},
        "expected_vulns": ["sql_injection"],
        "cvss_expected": 9.8
    },
    {
        "name": "Juice Shop XSS",
        "url": "http://localhost:3000/search",
        "method": "GET",
        "params": {"q": "test"},
        "expected_vulns": ["xss"],
        "cvss_expected": 6.1
    },
    {
        "name": "Juice Shop IDOR",
        "url": "http://localhost:3000/api/Users",
        "method": "GET",
        "params": {},
        "expected_vulns": ["idor", "broken_authentication"],
        "cvss_expected": 7.5
    }
]

# From your existing tests
TESTPHP_ENDPOINTS: List[Dict[str, Any]] = [
    {
        "name": "TestPHP SQLi Artist",
        "url": "http://testphp.vulnweb.com/artists.php",
        "method": "GET",
        "params": {"artist": "1"},
        "expected_vulns": ["sql_injection"],
        "cvss_expected": 9.8
    },
    {
        "name": "TestPHP XSS Search",
        "url": "http://testphp.vulnweb.com/search.php",
        "method": "GET",
        "params": {"searchFor": "test"},
        "expected_vulns": ["xss"],
        "cvss_expected": 6.1
    }
]


# ============================================================================
# SAFE TEST ENDPOINTS (False Positive Testing)
# ============================================================================

SAFE_ENDPOINTS: List[Dict[str, Any]] = [
    {
        "name": "Google Homepage",
        "url": "https://www.google.com",
        "method": "GET",
        "params": {},
        "expected_vulns": [],
        "description": "Major site with proper security"
    },
    {
        "name": "GitHub",
        "url": "https://github.com",
        "method": "GET",
        "params": {},
        "expected_vulns": [],
        "description": "Well-secured platform"
    },
    {
        "name": "Security Documentation",
        "url": "https://owasp.org/www-community/attacks/SQL_Injection",
        "method": "GET",
        "params": {},
        "expected_vulns": [],
        "description": "Should not flag SQL examples in documentation"
    }
]


# ============================================================================
# MOCK ENDPOINTS FOR OFFLINE TESTING
# ============================================================================

MOCK_VULNERABLE_ENDPOINTS: List[Dict[str, Any]] = [
    {
        "name": "Mock SQLi Error-Based",
        "url": "http://mock.local/api/products",
        "method": "GET",
        "params": {"id": "1"},
        "mock_response": {
            "status_code": 200,
            "text": "You have an error in your SQL syntax near '1'' at line 1"
        },
        "expected_vulns": ["sql_injection"],
        "expected_detection_method": "error_based"
    },
    {
        "name": "Mock XSS Reflected",
        "url": "http://mock.local/search",
        "method": "GET",
        "params": {"q": "test"},
        "mock_response": {
            "status_code": 200,
            "text": "<html><body>Search results for: {PAYLOAD}</body></html>"
        },
        "expected_vulns": ["xss"],
        "expected_context": "html_body"
    },
    {
        "name": "Mock Command Injection",
        "url": "http://mock.local/ping",
        "method": "GET",
        "params": {"host": "localhost"},
        "mock_response": {
            "status_code": 200,
            "text": "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        },
        "expected_vulns": ["command_injection"],
        "expected_detection_method": "error_based"
    }
]


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_endpoints_for_agent(agent_name: str) -> List[Dict[str, Any]]:
    """Get relevant endpoints for a specific agent."""
    mapping = {
        "sql_injection": [
            *[e for e in TESTPHP_ENDPOINTS if "sql" in e.get("expected_vulns", [])],
            *[e for e in JUICE_SHOP_ENDPOINTS if "sql" in e.get("expected_vulns", [])]
        ],
        "xss": [
            *[e for e in TESTPHP_ENDPOINTS if "xss" in e.get("expected_vulns", [])],
            *[e for e in JUICE_SHOP_ENDPOINTS if "xss" in e.get("expected_vulns", [])]
        ],
        "command_injection": [
            *[e for e in DVWA_ENDPOINTS if "command" in e.get("expected_vulns", [])]
        ]
    }
    
    return mapping.get(agent_name, [])


def get_safe_endpoints_for_testing() -> List[Dict[str, Any]]:
    """Get endpoints that should NOT trigger vulnerabilities."""
    return SAFE_ENDPOINTS
