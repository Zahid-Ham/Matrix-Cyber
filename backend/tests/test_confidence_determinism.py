
import sys
import os
import unittest

# Add parent directory to path to import backend modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scoring.confidence_calculator import ConfidenceCalculator, ConfidenceMethod, ConfidenceFactors, confidence_calculator

class TestConfidenceDeterminism(unittest.TestCase):

    def test_out_of_band_is_100(self):
        """Phase 4 Verification: Out-of-band must be 100."""
        factors = ConfidenceFactors(method=ConfidenceMethod.OUT_OF_BAND)
        self.assertEqual(confidence_calculator.calculate(factors), 100)

    def test_exploit_is_always_100(self):
        """Phase 4 Verification: Confirmed Exploit must be 100."""
        factors = ConfidenceFactors(method=ConfidenceMethod.CONFIRMED_EXPLOIT)
        self.assertEqual(confidence_calculator.calculate(factors), 100)
        
    def test_ai_is_capped(self):
        """Phase 4 Verification: AI Heuristic must be capped at 60."""
        factors = ConfidenceFactors(
            method=ConfidenceMethod.GENERIC_ERROR_OR_AI,
            confirmation_count=3 # Even with boost, should be capped
        )
        score = confidence_calculator.calculate(factors)
        self.assertEqual(score, 60, "AI Analysis must be capped at 60%")

    def test_reproducible_behavior_with_boost(self):
        """Reproducible Behavior (95) + 2 confirmations (6) = 101 -> 100 cap."""
        factors = ConfidenceFactors(
            method=ConfidenceMethod.REPRODUCIBLE_BEHAVIOR,
            confirmation_count=2
        )
        self.assertEqual(confidence_calculator.calculate(factors), 100)
        
    def test_environmental_penalty(self):
        """Confirmed Exploit (100) but in test environment (0.5 relevance) = 50."""
        factors = ConfidenceFactors(
            method=ConfidenceMethod.CONFIRMED_EXPLOIT,
            environmental_relevance=0.5
        )
        self.assertEqual(confidence_calculator.calculate(factors), 50)
        
    def test_evidence_quality_penalty(self):
        """Keyword match (40) with 0.5 quality = penalty 10 -> 30"""
        factors = ConfidenceFactors(
            method=ConfidenceMethod.KEYWORD_MATCH,
            evidence_quality=0.5
        )
        self.assertEqual(confidence_calculator.calculate(factors), 30)

if __name__ == "__main__":
    unittest.main()
