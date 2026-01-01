"""
CVSS Validation Utilities

Helpers for validating CVSS scores, vectors, and vulnerability contexts
in agent tests.
"""
from typing import Optional, Dict, Any
from agents.base_agent import AgentResult
from scoring.vulnerability_context import VulnerabilityContext


def validate_cvss_score(
    result: AgentResult,
    expected_score: float,
    tolerance: float = 0.5
) -> bool:
    """
    Validate CVSS score is within acceptable tolerance.
    
    Args:
        result: AgentResult to validate
        expected_score: Expected CVSS score (0.0-10.0)
        tolerance: Acceptable deviation (default 0.5)
        
    Returns:
        True if score is within tolerance
        
    Raises:
        AssertionError: If score is outside tolerance with detailed message
    """
    actual = result.cvss_score
    
    if actual is None:
        raise AssertionError(f"No CVSS score calculated for {result.title}")
    
    diff = abs(actual - expected_score)
    
    if diff > tolerance:
        raise AssertionError(
            f"CVSS score mismatch for '{result.title}':\n"
            f"  Expected: {expected_score}\n"
            f"  Actual: {actual}\n"
            f"  Difference: {diff} (tolerance: {tolerance})\n"
            f"  Vector: {result.cvss_vector}"
        )
    
    return True


def validate_cvss_vector(
    result: AgentResult,
    expected_vector: str
) -> bool:
    """
    Validate CVSS vector string matches expected.
    
    Args:
        result: AgentResult to validate
        expected_vector: Expected CVSS vector (e.g., "CVSS:3.1/AV:N/AC:L/...")
        
    Returns:
        True if vectors match
        
    Raises:
        AssertionError: If vectors don't match with detailed comparison
    """
    actual = result.cvss_vector
    
    if actual is None:
        raise AssertionError(f"No CVSS vector generated for {result.title}")
    
    # Normalize both vectors (remove spaces, ensure consistent format)
    actual_normalized = actual.replace(" ", "").upper()
    expected_normalized = expected_vector.replace(" ", "").upper()
    
    if actual_normalized != expected_normalized:
        # Find differences
        actual_parts = dict(part.split(":") for part in actual_normalized.split("/")[1:])
        expected_parts = dict(part.split(":") for part in expected_normalized.split("/")[1:])
        
        differences = []
        for key in set(actual_parts.keys()) | set(expected_parts.keys()):
            actual_val = actual_parts.get(key, "MISSING")
            expected_val = expected_parts.get(key, "MISSING")
            if actual_val != expected_val:
                differences.append(f"  {key}: {actual_val} != {expected_val}")
        
        raise AssertionError(
            f"CVSS vector mismatch for '{result.title}':\n"
            f"  Expected: {expected_vector}\n"
            f"  Actual: {actual}\n"
            f"  Differences:\n" + "\n".join(differences)
        )
    
    return True


def validate_scope_change(
    context: VulnerabilityContext,
    should_be_changed: bool
) -> bool:
    """
    Validate Scope:Changed detection is correct.
    
    Args:
        context: VulnerabilityContext to validate
        should_be_changed: Whether scope SHOULD be changed
        
    Returns:
        True if scope change detection is correct
        
    Raises:
        AssertionError: If scope change is incorrect
    """
    is_changed = context.escapes_security_boundary
    
    if is_changed != should_be_changed:
        raise AssertionError(
            f"Scope change detection incorrect for {context.vulnerability_type}:\n"
            f"  Expected Scope:{'Changed' if should_be_changed else 'Unchanged'}\n"
            f"  Actual: escapes_security_boundary={is_changed}\n"
            f"  Context: {context.detection_method}"
        )
    
    return True


def validate_privilege_required(
    context: VulnerabilityContext,
    expected_pr: str  # "N", "L", or "H"
) -> bool:
    """
    Validate Privilege Required (PR) metric is correct.
    
    Args:
        context: VulnerabilityContext to validate
        expected_pr: Expected PR value ("N", "L", "H")
        
    Returns:
        True if PR is correct
        
    Raises:
        AssertionError: If PR is incorrect
    """
    # Map context to CVSS PR metric
    if not context.requires_authentication:
        actual_pr = "N"
    elif context.authentication_level == "none":
        actual_pr = "N"
    elif context.authentication_level in ["low", "user"]:
        actual_pr = "L"
    elif context.authentication_level in ["high", "admin"]:
        actual_pr = "H"
    else:
        actual_pr = "UNKNOWN"
    
    if actual_pr != expected_pr:
        raise AssertionError(
            f"Privilege Required mismatch for {context.vulnerability_type}:\n"
            f"  Expected PR:{expected_pr}\n"
            f"  Actual PR:{actual_pr}\n"
            f"  requires_authentication: {context.requires_authentication}\n"
            f"  authentication_level: {context.authentication_level}"
        )
    
    return True


def validate_user_interaction(
    context: VulnerabilityContext,
    expected_ui: str  # "N" or "R"
) -> bool:
    """
    Validate User Interaction (UI) metric is correct.
    
    Args:
        context: VulnerabilityContext to validate
        expected_ui: Expected UI value ("N" or "R")
        
    Returns:
        True if UI is correct
        
    Raises:
        AssertionError: If UI is incorrect
    """
    actual_ui = "R" if context.requires_user_interaction else "N"
    
    if actual_ui != expected_ui:
        raise AssertionError(
            f"User Interaction mismatch for {context.vulnerability_type}:\n"
            f"  Expected UI:{expected_ui}\n"
            f"  Actual UI:{actual_ui}\n"
            f"  requires_user_interaction: {context.requires_user_interaction}"
        )
    
    return True


def assert_cvss_metrics(
    result: AgentResult,
    expected: Dict[str, Any]
) -> bool:
    """
    Comprehensive CVSS validation helper.
    
    Args:
        result: AgentResult to validate
        expected: Dictionary with expected values:
            - score: Expected CVSS score
            - vector: Expected CVSS vector (optional)
            - scope_changed: Expected scope change (optional)
            - pr: Expected Privilege Required (optional)
            - ui: Expected User Interaction (optional)
            
    Returns:
        True if all validations pass
        
    Example:
        assert_cvss_metrics(result, {
            "score": 9.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "scope_changed": False,
            "pr": "N",
            "ui": "N"
        })
    """
    # Validate score
    if "score" in expected:
        validate_cvss_score(result, expected["score"])
    
    # Validate vector
    if "vector" in expected:
        validate_cvss_vector(result, expected["vector"])
    
    # Validate individual metrics by parsing the vector
    if result.cvss_vector and result.cvss_metrics:
        if "scope_changed" in expected:
            actual_scope = result.cvss_metrics.get("S", "U")
            expected_scope = "C" if expected["scope_changed"] else "U"
            if actual_scope != expected_scope:
                raise AssertionError(
                    f"Scope mismatch for '{result.title}': "
                    f"Expected S:{expected_scope}, Actual S:{actual_scope}"
                )
        
        if "pr" in expected:
            actual_pr = result.cvss_metrics.get("PR", "UNKNOWN")
            if actual_pr != expected["pr"]:
                raise AssertionError(
                    f"Privilege Required mismatch for '{result.title}': "
                    f"Expected PR:{expected['pr']}, Actual PR:{actual_pr}"
                )
        
        if "ui" in expected:
            actual_ui = result.cvss_metrics.get("UI", "UNKNOWN")
            if actual_ui != expected["ui"]:
                raise AssertionError(
                    f"User Interaction mismatch for '{result.title}': "
                    f"Expected UI:{expected['ui']}, Actual UI:{actual_ui}"
                )
    
    return True
