"""
CVSS v3.1 Scoring Module for Matrix Security Scanner.

Provides context-based CVSS calculation instead of severity banding.
Now also includes Evidence-Based Confidence Calibration.
"""
from .vulnerability_context import VulnerabilityContext
from .cvss_calculator import CVSSCalculator, CVSSResult
from .metric_determiners import MetricDeterminers
from .justification_generator import JustificationGenerator
from .confidence_calculator import ConfidenceCalculator, ConfidenceMethod, ConfidenceFactors

__all__ = [
    "VulnerabilityContext",
    "CVSSCalculator", 
    "CVSSResult",
    "MetricDeterminers",
    "JustificationGenerator",
    "ConfidenceCalculator",
    "ConfidenceMethod",
    "ConfidenceFactors",
]
