"""
Deterministic Confidence Calculator

This module provides the logic for calculating vulnerability confidence scores
based on rigid, evidence-based criteria rather than AI estimation.

Philosophy: "Confidence comes from Evidence Strength, not LLM Opinion."
"""
from enum import Enum
from dataclasses import dataclass
from typing import Optional


class ConfidenceMethod(Enum):
    """
    Hierarchy of detection methods ordered by reliability.
    """
    # Absolute confidence: Out-of-band interaction (e.g., DNS/HTTP callback to external listener)
    OUT_OF_BAND = "out_of_band"
    
    # Highest confidence: Payloads executed and confirmed within the request/response cycle
    CONFIRMED_EXPLOIT = "confirmed_exploit"
    
    # Very High confidence: Statistical timing analysis or behavioral changes with 3+ confirmations
    REPRODUCIBLE_BEHAVIOR = "reproducible_behavior"
    
    # High confidence: Logic/Boolean analysis showed definitive behavioral difference
    LOGIC_MATCH = "logic_match"
    
    # High/Medium confidence: Database/Framework specific error message found
    SPECIFIC_ERROR = "specific_error"
    
    # Medium confidence: Generic errors ("Syntax error") or AI heuristic analysis
    GENERIC_ERROR_OR_AI = "generic_error_or_ai"
    
    # Low confidence: Simple keyword matching/regex without validation
    KEYWORD_MATCH = "keyword_match"


@dataclass
class ConfidenceFactors:
    """
    Factors influencing the final confidence score.
    """
    method: ConfidenceMethod
    """The primary method used for detection."""
    
    evidence_quality: float = 1.0
    """Quality of evidence (0.0 to 1.0). E.g., entropy score for secrets."""
    
    confirmation_count: int = 0
    """Number of times the finding was verified with different payloads/methods."""
    
    environmental_relevance: float = 1.0
    """Relevance based on context (1.0 for prod, 0.5 for /test/, etc.)."""


class ConfidenceCalculator:
    """
    Calculates deterministic confidence scores (0-100).
    """
    
    # Base scores for each method
    BASE_SCORES = {
        ConfidenceMethod.OUT_OF_BAND: 100,
        ConfidenceMethod.CONFIRMED_EXPLOIT: 100,
        ConfidenceMethod.REPRODUCIBLE_BEHAVIOR: 95,
        ConfidenceMethod.LOGIC_MATCH: 90,
        ConfidenceMethod.SPECIFIC_ERROR: 80,
        ConfidenceMethod.GENERIC_ERROR_OR_AI: 60,
        ConfidenceMethod.KEYWORD_MATCH: 40
    }
    
    # Maximum caps (hard limits)
    MAX_CAPS = {
        ConfidenceMethod.GENERIC_ERROR_OR_AI: 60,
        ConfidenceMethod.KEYWORD_MATCH: 40
    }

    @classmethod
    def calculate(cls, factors: ConfidenceFactors) -> int:
        """
        Calculate the confidence score based on provided factors.
        """
        base_score = cls.BASE_SCORES[factors.method]
        score = base_score
        
        # 1. Evidence Quality Penalty (Entropy, Signal/Noise)
        if factors.evidence_quality < 1.0:
            penalty = (1.0 - factors.evidence_quality) * 20
            score -= penalty
            
        # 2. Confirmation Boost (Multivariate proof)
        # Cap boost at 10 points
        if factors.confirmation_count > 0:
            boost = min(factors.confirmation_count * 3, 10)
            score += boost
            
        # 3. Environmental Relevance Scaling
        # Penalize findings in /test/, /example/, or mock files
        if factors.environmental_relevance < 1.0:
            score *= factors.environmental_relevance
            
        # 4. Apply Caps
        if factors.method in cls.MAX_CAPS:
            max_cap = cls.MAX_CAPS[factors.method]
            score = min(score, max_cap)
            
        # Global bounds
        return max(0, min(100, int(score)))

# Singleton instance
confidence_calculator = ConfidenceCalculator()
