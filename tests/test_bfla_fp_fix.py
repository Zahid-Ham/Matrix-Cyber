
import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock, patch
from backend.agents.api_security_agent import APISecurityAgent
from models.vulnerability import VulnerabilityType, Severity

class MockResponse:
    def __init__(self, text, status_code):
        self.text = text
        self.status_code = status_code

class TestBFLAFP(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.agent = APISecurityAgent()
        # Mock create_result to return something simple
        self.agent.create_result = MagicMock(side_effect=lambda **kwargs: kwargs)
        # Mock _build_api_context
        self.agent._build_api_context = MagicMock(return_value={})

    async def test_spa_false_positive_suppression(self):
        """Test that generic SPA shells are NOT flagged as BFLA."""
        spa_content = '<html><body><div id="root"></div><script src="app.js"></script></body></html>'
        
        # Mock make_request to return SPA shell for ALL routes (including baseline)
        self.agent.make_request = AsyncMock(return_value=MockResponse(spa_content, 200))
        
        results = await self.agent._test_function_level_authz("https://example.com")
        
        # Should be 0 results because it matches baseline and looks like SPA
        self.assertEqual(len(results), 0, f"Expected 0 findings for SPA, got {len(results)}")

    async def test_real_admin_detection(self):
        """Test that real admin pages (not matching baseline) ARE flagged."""
        baseline_content = "Not found"
        admin_content = '{"status": "admin_panel", "users": []}' # JSON/Admin content
        
        async def mock_request(url, **kwargs):
            if "non_existent_path" in url:
                return MockResponse(baseline_content, 404)
            if "/admin" in url:
                return MockResponse(admin_content, 200)
            return MockResponse(baseline_content, 404)

        self.agent.make_request = AsyncMock(side_effect=mock_request)
        
        results = await self.agent._test_function_level_authz("https://example.com")
        
        # Should find at least one BFLA for /admin
        self.assertTrue(len(results) > 0, "Expected findings for real admin panel")
        self.assertEqual(results[0]['url'], "https://example.com/admin")

    async def test_spa_specifically_enabled_admin(self):
        """
        Test case where site returns 404 for baseline but 200 OK with SPA shell 
        specifically for /admin. This is common in some misconfigurations.
        """
        baseline_content = "404 Not Found"
        spa_content = '<html><body><div id="root"></div><script src="app.js"></script></body></html>'
        
        async def mock_request(url, **kwargs):
            if "non_existent_path" in url:
                return MockResponse(baseline_content, 404)
            if "/admin" in url:
                return MockResponse(spa_content, 200)
            return MockResponse(baseline_content, 404)

        self.agent.make_request = AsyncMock(side_effect=mock_request)
        
        results = await self.agent._test_function_level_authz("https://example.com")
        
        # If baseline was 404 but /admin is 200 (even if SPA shell), we should probably flag it 
        # but maybe with lower confidence. In my implementation, if it looks like SPA and 
        # baseline was NOT 200, it should still be flagged or checked.
        # Actually my logic is: if is_spa: if baseline_status == 200 and similarity > 0.7: continue
        # So if baseline_status is NOT 200 (it's 404), it WILL be flagged.
        
        self.assertTrue(len(results) > 0, "Expected findings when /admin is specifically 200 vs baseline 404")

if __name__ == "__main__":
    unittest.main()
