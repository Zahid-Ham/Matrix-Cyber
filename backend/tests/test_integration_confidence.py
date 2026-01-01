
import unittest
import sys
import os
from unittest.mock import MagicMock

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agents.base_agent import BaseSecurityAgent
from scoring import ConfidenceMethod

class MockAgent(BaseSecurityAgent):
    """Minimal concrete implementation for testing."""
    agent_name = "mock"
    agent_description = "mock"
    vulnerability_types = []
    
    async def scan(self, *args, **kwargs):
        return []

class TestAgentConfidenceIntegration(unittest.TestCase):
    def setUp(self):
        # We need to mock settings or provide dummy values if __init__ requires them
        # BaseSecurityAgent usually requires minimal args or handles defaults
        self.agent = MockAgent()

    def test_calculate_confidence_delegation(self):
        """Test that calculate_confidence returns expected values from ConfidenceCalculator."""
        # Exploit = 100
        score = self.agent.calculate_confidence(ConfidenceMethod.CONFIRMED_EXPLOIT)
        self.assertEqual(score, 100)
    
    def test_environmental_auto_penalty(self):
        """Verify that file_path triggers automatic environmental penalty."""
        # Baseline: Exploit = 100
        
        # In a test file -> 50% penalty (rel=0.5)
        score = self.agent.calculate_confidence(
            ConfidenceMethod.CONFIRMED_EXPLOIT,
            file_path="src/tests/test_api.py"
        )
        self.assertEqual(score, 50, "Findings in test files should be penalized")
        
        # In a generic file -> No penalty
        score = self.agent.calculate_confidence(
            ConfidenceMethod.CONFIRMED_EXPLOIT,
            file_path="src/main/app.py"
        )
        self.assertEqual(score, 100)

    def test_ai_cap_via_method_call(self):
        """Verify the AI cap remains robust."""
        score = self.agent.calculate_confidence(
            method=ConfidenceMethod.GENERIC_ERROR_OR_AI,
            evidence_quality=0.5
        )
        # Base 60 - (1-0.5)*20 = 50.
        self.assertEqual(score, 50)

if __name__ == "__main__":
    unittest.main()
