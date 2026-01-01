"""
CVSS Metric Determiners - Deterministic functions for each CVSS v3.1 metric.

Each function takes a VulnerabilityContext and returns the appropriate metric value.
These are rule-based, not AI-based, ensuring reproducible scores.
"""
from typing import Dict, Any
from .vulnerability_context import VulnerabilityContext


class MetricDeterminers:
    """
    Deterministic metric determination for CVSS v3.1.
    
    Each method implements the decision logic for one CVSS metric based on
    vulnerability context. The logic follows FIRST.org guidelines.
    """
    
    # Vulnerability types that always require user interaction
    USER_INTERACTION_REQUIRED = {
        "xss", "xss_reflected", "xss_stored", "xss_dom",
        "csrf", "clickjacking", "open_redirect", "phishing"
    }
    
    # Vulnerability types that typically escape security boundaries
    SCOPE_CHANGED_TYPES = {
        "command_injection", "os_command_injection",
        "container_escape", "vm_escape"
    }
    
    @classmethod
    def determine_attack_vector(cls, ctx: VulnerabilityContext) -> str:
        """
        Determine Attack Vector (AV) metric.
        
        N (Network): Remotely exploitable over network
        A (Adjacent): Requires local network access
        L (Local): Requires local system access
        P (Physical): Requires physical device access
        
        Returns:
            "N", "A", "L", or "P"
        """
        if ctx.requires_physical_access:
            return "P"
        
        if ctx.requires_local_network:
            return "A"
        
        if not ctx.network_accessible:
            return "L"
        
        # Default for web vulnerabilities - network accessible
        return "N"
    
    @classmethod
    def determine_attack_complexity(cls, ctx: VulnerabilityContext) -> str:
        """
        Determine Attack Complexity (AC) metric.
        
        L (Low): No special conditions, reliable exploitation
        H (High): Requires special conditions or has low success rate
        
        Returns:
            "L" or "H"
        """
        complexity_factors = 0
        
        # Factors that increase complexity
        if ctx.behind_waf and "waf" in ctx.security_controls_bypassed:
            complexity_factors += 1  # Had to evade WAF
        
        if ctx.requires_specific_conditions:
            complexity_factors += 1
        
        if ctx.exploitation_difficulty == "difficult":
            complexity_factors += 2
        elif ctx.exploitation_difficulty == "moderate":
            complexity_factors += 1
        
        # Factors that indicate low complexity
        if ctx.detection_method == "error_based":
            return "L"  # Error messages make exploitation trivial
        
        if ctx.payload_succeeded and ctx.exploitation_difficulty == "trivial":
            return "L"
        
        # High complexity if 2+ factors
        return "H" if complexity_factors >= 2 else "L"
    
    @classmethod
    def determine_privileges_required(cls, ctx: VulnerabilityContext) -> str:
        """
        Determine Privileges Required (PR) metric.
        
        N (None): No authentication required
        L (Low): Basic user account required
        H (High): Admin/privileged account required
        
        Returns:
            "N", "L", or "H"
        """
        if not ctx.requires_authentication:
            return "N"
        
        auth_level = ctx.authentication_level.lower()
        
        if auth_level in ["admin", "administrator", "privileged", "elevated", "high"]:
            return "H"
        
        if auth_level in ["user", "basic", "standard", "low"]:
            return "L"
        
        # Check endpoint patterns for privilege hints
        endpoint_lower = ctx.endpoint.lower()
        if any(pattern in endpoint_lower for pattern in ["/admin", "/internal", "/management", "/system"]):
            return "H"
        
        return "N"  # Default to no privileges if unclear
    
    @classmethod
    def determine_user_interaction(cls, ctx: VulnerabilityContext) -> str:
        """
        Determine User Interaction (UI) metric.
        
        N (None): No user interaction needed
        R (Required): Victim must perform action
        
        Returns:
            "N" or "R"
        """
        # XSS, CSRF, and similar ALWAYS require user interaction
        vuln_type = ctx.vulnerability_type.lower()
        if vuln_type in cls.USER_INTERACTION_REQUIRED:
            return "R"
        
        if ctx.requires_user_interaction or ctx.requires_social_engineering:
            return "R"
        
        # Direct exploitation vulnerabilities
        if vuln_type in ["sqli", "sql_injection", "ssrf", "command_injection", "rce"]:
            return "N"
        
        return "N"  # Default: no interaction
    
    @classmethod
    def determine_scope(cls, ctx: VulnerabilityContext) -> str:
        """
        Determine Scope (S) metric.
        
        U (Unchanged): Impact limited to vulnerable component
        C (Changed): Impact escapes to other components
        
        This is THE most important metric for high CVSS scores.
        
        Returns:
            "U" or "C"
        """
        # Explicit scope change indicators
        if ctx.escapes_security_boundary:
            return "C"
        
        if ctx.can_execute_os_commands:
            return "C"  # Database -> OS is scope change
        
        if ctx.can_access_cloud_metadata:
            return "C"  # App -> Cloud infrastructure
        
        # Command injection always changes scope (app -> OS)
        vuln_type = ctx.vulnerability_type.lower()
        if vuln_type in cls.SCOPE_CHANGED_TYPES:
            return "C"
        
        # SSRF to internal network/cloud metadata
        if vuln_type in ["ssrf", "server_side_request_forgery"]:
            if ctx.can_access_internal_network or ctx.can_access_cloud_metadata:
                return "C"
        
        # XSS affecting other origins
        if vuln_type.startswith("xss") and ctx.affects_other_users:
            # Stored XSS affecting other users is still same origin typically
            # Only Changed if it affects different origins
            if ctx.additional_context.get("affects_different_origin"):
                return "C"
        
        return "U"  # Default: unchanged
    
    @classmethod
    def determine_confidentiality_impact(cls, ctx: VulnerabilityContext) -> str:
        """
        Determine Confidentiality Impact (C) metric.
        
        N (None): No information disclosure
        L (Low): Some information disclosed
        H (High): All information within scope disclosed
        
        Returns:
            "N", "L", or "H"
        """
        if not ctx.data_exposed:
            return "N"
        
        # High impact data categories
        high_impact_keywords = [
            "database", "credentials", "credential", "passwords", "password", "keys", "key", "secrets", "secret",
            "pii", "payment", "credit_card", "ssn", "health_records",
            "aws_credentials", "api_keys", "api_key", "tokens", "token", "private_keys", "private_key"
        ]
        
        exposed_lower = [d.lower() for d in ctx.data_exposed]
        
        # Check for high-impact data
        has_high_impact = any(
            keyword in " ".join(exposed_lower)
            for keyword in high_impact_keywords
        )
        
        if has_high_impact:
            return "H"
        
        # SQL injection typically has high confidentiality impact
        vuln_type = ctx.vulnerability_type.lower()
        if vuln_type in ["sqli", "sql_injection"] and "database" in exposed_lower:
            return "H"  # Can read entire database
        
        # SSRF to cloud metadata = high (IAM creds)
        if vuln_type in ["ssrf"] and ctx.can_access_cloud_metadata:
            return "H"
        
        # Limited disclosure
        if len(ctx.data_exposed) <= 2:
            return "L"
        
        return "H"  # Default to high for confirmed data exposure
    
    @classmethod
    def determine_integrity_impact(cls, ctx: VulnerabilityContext) -> str:
        """
        Determine Integrity Impact (I) metric.
        
        N (None): No data modification possible
        L (Low): Limited data modification
        H (High): Complete data modification possible
        
        Returns:
            "N", "L", or "H"
        """
        if not ctx.data_modifiable:
            # XSS has some integrity impact (can modify page content)
            vuln_type = ctx.vulnerability_type.lower()
            if vuln_type.startswith("xss"):
                return "L"
            return "N"
        
        modifiable_lower = [d.lower() for d in ctx.data_modifiable]
        
        # High impact: can modify critical data
        if any(word in " ".join(modifiable_lower) for word in 
               ["database", "filesystem", "config", "credentials", "credential", "admin", "account", "profile", "settings"]):
            return "H"
        
        # Command injection can modify anything
        vuln_type = ctx.vulnerability_type.lower()
        if vuln_type in ["command_injection", "os_command_injection", "rce"]:
            return "H"
        
        # SQL injection with write access
        if vuln_type in ["sqli", "sql_injection"] and "database" in modifiable_lower:
            return "H"
        
        return "L"  # Limited modification
    
    @classmethod
    def determine_availability_impact(cls, ctx: VulnerabilityContext) -> str:
        """
        Determine Availability Impact (A) metric.
        
        N (None): No service disruption
        L (Low): Reduced performance
        H (High): Complete denial of service
        
        Returns:
            "N", "L", or "H"
        """
        vuln_type = ctx.vulnerability_type.lower()
        
        # Command injection can always affect availability
        if vuln_type in ["command_injection", "os_command_injection", "rce"]:
            return "H"
        
        if ctx.service_disruption_possible:
            # Check if it's complete or partial
            if ctx.additional_context.get("dos_severity") == "complete":
                return "H"
            return "L"
        
        # SQL injection with DROP/DELETE capability
        if vuln_type in ["sqli", "sql_injection"]:
            if ctx.additional_context.get("can_delete_data"):
                return "H"
        
        # Most web vulnerabilities don't inherently affect availability
        if vuln_type in ["xss", "csrf", "idor", "open_redirect"]:
            return "N"
        
        return "N"
    
    @classmethod
    def determine_all_metrics(cls, ctx: VulnerabilityContext) -> Dict[str, str]:
        """
        Determine all 8 CVSS metrics for a vulnerability context.
        
        Returns:
            Dictionary with keys: AV, AC, PR, UI, S, C, I, A
        """
        return {
            "AV": cls.determine_attack_vector(ctx),
            "AC": cls.determine_attack_complexity(ctx),
            "PR": cls.determine_privileges_required(ctx),
            "UI": cls.determine_user_interaction(ctx),
            "S": cls.determine_scope(ctx),
            "C": cls.determine_confidentiality_impact(ctx),
            "I": cls.determine_integrity_impact(ctx),
            "A": cls.determine_availability_impact(ctx),
        }
