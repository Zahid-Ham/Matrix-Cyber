"""
CVSS v3.1 Calculator - Main calculation logic.

Implements the official CVSS v3.1 base score formula from FIRST.org.
This replaces severity-banding with proper context-based calculation.
"""
import math
from dataclasses import dataclass, field
from typing import Dict, Optional
from enum import Enum

from .vulnerability_context import VulnerabilityContext
from .metric_determiners import MetricDeterminers
from .justification_generator import JustificationGenerator


class CVSSSeverity(str, Enum):
    """CVSS severity ratings based on score ranges."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CVSSResult:
    """
    Result of CVSS calculation.
    
    Contains the score, vector string, individual metrics, and justifications.
    """
    score: float
    """CVSS base score (0.0 - 10.0)"""
    
    severity: str
    """Severity label: None, Low, Medium, High, Critical"""
    
    vector: str
    """Full CVSS vector string, e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"""
    
    metrics: Dict[str, str]
    """Individual metrics: {AV, AC, PR, UI, S, C, I, A}"""
    
    metrics_expanded: Dict[str, str] = field(default_factory=dict)
    """Human-readable metric names: {attack_vector: 'Network', ...}"""
    
    justifications: Dict[str, str] = field(default_factory=dict)
    """Explanation for each metric selection"""
    
    exploitability_score: float = 0.0
    """CVSS exploitability sub-score"""
    
    impact_score: float = 0.0
    """CVSS impact sub-score"""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "score": self.score,
            "severity": self.severity,
            "vector": self.vector,
            "metrics": self.metrics,
            "metrics_expanded": self.metrics_expanded,
            "justifications": self.justifications,
            "exploitability_score": round(self.exploitability_score, 1),
            "impact_score": round(self.impact_score, 1),
        }


class CVSSCalculator:
    """
    CVSS v3.1 Base Score Calculator.
    
    Implements the official CVSS v3.1 formula from FIRST.org.
    Reference: https://www.first.org/cvss/v3.1/specification-document
    
    Example:
        calculator = CVSSCalculator()
        context = VulnerabilityContext(
            vulnerability_type="sqli",
            detection_method="error_based",
            requires_authentication=False,
            data_exposed=["database"]
        )
        result = calculator.calculate(context)
        print(f"Score: {result.score}, Vector: {result.vector}")
    """
    
    # Metric value mappings per CVSS v3.1 specification
    AV_VALUES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    AC_VALUES = {"L": 0.77, "H": 0.44}
    
    # PR values differ based on Scope
    PR_VALUES_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_VALUES_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    
    UI_VALUES = {"N": 0.85, "R": 0.62}
    CIA_VALUES = {"N": 0.0, "L": 0.22, "H": 0.56}
    
    # Metric code to name mapping
    METRIC_NAMES = {
        "AV": {
            "N": "Network",
            "A": "Adjacent",
            "L": "Local", 
            "P": "Physical"
        },
        "AC": {
            "L": "Low",
            "H": "High"
        },
        "PR": {
            "N": "None",
            "L": "Low",
            "H": "High"
        },
        "UI": {
            "N": "None",
            "R": "Required"
        },
        "S": {
            "U": "Unchanged",
            "C": "Changed"
        },
        "C": {
            "N": "None",
            "L": "Low",
            "H": "High"
        },
        "I": {
            "N": "None",
            "L": "Low",
            "H": "High"
        },
        "A": {
            "N": "None",
            "L": "Low",
            "H": "High"
        }
    }
    
    def calculate(self, context: VulnerabilityContext) -> CVSSResult:
        """
        Calculate CVSS v3.1 base score from vulnerability context.
        
        Args:
            context: VulnerabilityContext with all relevant information
            
        Returns:
            CVSSResult with score, vector, metrics, and justifications
        """
        # Step 1: Determine all metrics
        metrics = MetricDeterminers.determine_all_metrics(context)
        
        # Step 2: Calculate numeric values
        scope = metrics["S"]
        
        av = self.AV_VALUES[metrics["AV"]]
        ac = self.AC_VALUES[metrics["AC"]]
        ui = self.UI_VALUES[metrics["UI"]]
        
        # PR value depends on Scope
        if scope == "C":
            pr = self.PR_VALUES_CHANGED[metrics["PR"]]
        else:
            pr = self.PR_VALUES_UNCHANGED[metrics["PR"]]
        
        c = self.CIA_VALUES[metrics["C"]]
        i = self.CIA_VALUES[metrics["I"]]
        a = self.CIA_VALUES[metrics["A"]]
        
        # Step 3: Calculate Impact Sub-Score (ISS)
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        
        # Step 4: Calculate Impact based on Scope
        if scope == "U":
            impact = 6.42 * iss
        else:  # scope == "C"
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
        
        # Step 5: Calculate Exploitability
        exploitability = 8.22 * av * ac * pr * ui
        
        # Step 6: Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        else:
            if scope == "U":
                base_score = min(impact + exploitability, 10.0)
            else:  # scope == "C"
                base_score = min(1.08 * (impact + exploitability), 10.0)
        
        # Step 7: Round up to nearest 0.1
        base_score = self._roundup(base_score)
        
        # Step 8: Generate vector string
        vector = self._generate_vector(metrics)
        
        # Step 9: Determine severity
        severity = self._score_to_severity(base_score)
        
        # Step 10: Expand metric names
        metrics_expanded = self._expand_metrics(metrics)
        
        # Step 11: Generate justifications
        justifications = JustificationGenerator.generate_all_justifications(
            context, metrics
        )
        
        return CVSSResult(
            score=base_score,
            severity=severity,
            vector=vector,
            metrics=metrics,
            metrics_expanded=metrics_expanded,
            justifications=justifications,
            exploitability_score=self._roundup(exploitability),
            impact_score=self._roundup(impact) if impact > 0 else 0.0
        )
    
    def calculate_from_metrics(
        self, 
        av: str, 
        ac: str, 
        pr: str, 
        ui: str, 
        s: str, 
        c: str, 
        i: str, 
        a: str
    ) -> CVSSResult:
        """
        Calculate CVSS score directly from metric values.
        
        Useful when you already have the metrics and just need the score.
        
        Args:
            av: Attack Vector (N/A/L/P)
            ac: Attack Complexity (L/H)
            pr: Privileges Required (N/L/H)
            ui: User Interaction (N/R)
            s: Scope (U/C)
            c: Confidentiality (N/L/H)
            i: Integrity (N/L/H)
            a: Availability (N/L/H)
            
        Returns:
            CVSSResult with calculated score
        """
        # Create a minimal context for justification generation
        context = VulnerabilityContext(
            vulnerability_type="unknown",
            detection_method="manual"
        )
        
        metrics = {
            "AV": av.upper(),
            "AC": ac.upper(),
            "PR": pr.upper(),
            "UI": ui.upper(),
            "S": s.upper(),
            "C": c.upper(),
            "I": i.upper(),
            "A": a.upper()
        }
        
        # Recalculate using the context-based method with overridden metrics
        # For direct metric calculation, we bypass context determination
        scope = metrics["S"]
        
        av_val = self.AV_VALUES[metrics["AV"]]
        ac_val = self.AC_VALUES[metrics["AC"]]
        ui_val = self.UI_VALUES[metrics["UI"]]
        
        if scope == "C":
            pr_val = self.PR_VALUES_CHANGED[metrics["PR"]]
        else:
            pr_val = self.PR_VALUES_UNCHANGED[metrics["PR"]]
        
        c_val = self.CIA_VALUES[metrics["C"]]
        i_val = self.CIA_VALUES[metrics["I"]]
        a_val = self.CIA_VALUES[metrics["A"]]
        
        iss = 1 - ((1 - c_val) * (1 - i_val) * (1 - a_val))
        
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
        
        exploitability = 8.22 * av_val * ac_val * pr_val * ui_val
        
        if impact <= 0:
            base_score = 0.0
        else:
            if scope == "U":
                base_score = min(impact + exploitability, 10.0)
            else:
                base_score = min(1.08 * (impact + exploitability), 10.0)
        
        base_score = self._roundup(base_score)
        vector = self._generate_vector(metrics)
        severity = self._score_to_severity(base_score)
        metrics_expanded = self._expand_metrics(metrics)
        
        return CVSSResult(
            score=base_score,
            severity=severity,
            vector=vector,
            metrics=metrics,
            metrics_expanded=metrics_expanded,
            justifications={},  # No justifications for direct calculation
            exploitability_score=self._roundup(exploitability),
            impact_score=self._roundup(impact) if impact > 0 else 0.0
        )
    
    def _roundup(self, value: float) -> float:
        """
        Round up to nearest 0.1 per CVSS specification.
        
        CVSS uses "round up" (ceiling) to one decimal place.
        """
        return math.ceil(value * 10) / 10
    
    def _generate_vector(self, metrics: Dict[str, str]) -> str:
        """Generate CVSS v3.1 vector string."""
        return (
            f"CVSS:3.1/"
            f"AV:{metrics['AV']}/"
            f"AC:{metrics['AC']}/"
            f"PR:{metrics['PR']}/"
            f"UI:{metrics['UI']}/"
            f"S:{metrics['S']}/"
            f"C:{metrics['C']}/"
            f"I:{metrics['I']}/"
            f"A:{metrics['A']}"
        )
    
    def _score_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity rating."""
        if score == 0.0:
            return CVSSSeverity.NONE.value
        elif score <= 3.9:
            return CVSSSeverity.LOW.value
        elif score <= 6.9:
            return CVSSSeverity.MEDIUM.value
        elif score <= 8.9:
            return CVSSSeverity.HIGH.value
        else:
            return CVSSSeverity.CRITICAL.value
    
    def _expand_metrics(self, metrics: Dict[str, str]) -> Dict[str, str]:
        """Expand metric codes to human-readable names."""
        return {
            "attack_vector": self.METRIC_NAMES["AV"][metrics["AV"]],
            "attack_complexity": self.METRIC_NAMES["AC"][metrics["AC"]],
            "privileges_required": self.METRIC_NAMES["PR"][metrics["PR"]],
            "user_interaction": self.METRIC_NAMES["UI"][metrics["UI"]],
            "scope": self.METRIC_NAMES["S"][metrics["S"]],
            "confidentiality_impact": self.METRIC_NAMES["C"][metrics["C"]],
            "integrity_impact": self.METRIC_NAMES["I"][metrics["I"]],
            "availability_impact": self.METRIC_NAMES["A"][metrics["A"]],
        }


    def parse_vector(self, vector_str: str) -> CVSSResult:
        """
        Parse a CVSS v3.1 vector string and calculate the result.
        
        Args:
            vector_str: e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
            
        Returns:
            CVSSResult
        """
        try:
            # Strip prefix
            if vector_str.startswith("CVSS:3.1/"):
                vector_str = vector_str[9:]
            elif vector_str.startswith("CVSS:3.0/"):
                # Treat 3.0 as 3.1 for now (formulas are similar enough for base)
                vector_str = vector_str[9:]
                
            metrics = {}
            parts = vector_str.split('/')
            
            for part in parts:
                if ':' in part:
                    key, val = part.split(':', 1)
                    metrics[key] = val
            
            # Ensure all required metrics are present
            required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
            if not all(k in metrics for k in required):
                raise ValueError(f"Missing metrics in vector: {vector_str}")
                
            return self.calculate_from_metrics(
                av=metrics["AV"],
                ac=metrics["AC"],
                pr=metrics["PR"],
                ui=metrics["UI"],
                s=metrics["S"],
                c=metrics["C"],
                i=metrics["I"],
                a=metrics["A"]
            )
            
        except Exception as e:
            # Fallback for invalid vectors
            from logging import getLogger
            logger = getLogger(__name__)
            logger.warning(f"Failed to parse CVSS vector '{vector_str}': {e}")
            
            # Return empty/zero result
            return CVSSResult(
                score=0.0,
                severity=CVSSSeverity.NONE.value,
                vector=vector_str,
                metrics={},
                metrics_expanded={},
                justifications={"Error": f"Could not parse vector: {e}"}
            )


# Singleton calculator instance
cvss_calculator = CVSSCalculator()
