"""
Justification Generator - Human-readable explanations for CVSS metric selections.

Generates clear explanations for why each metric was chosen, which appear in
scan reports alongside the CVSS vector.
"""
from typing import Dict
from .vulnerability_context import VulnerabilityContext


class JustificationGenerator:
    """
    Generate human-readable justifications for CVSS metric selections.
    
    These justifications explain to users (and auditors) why specific
    metric values were chosen, making CVSS scores transparent and verifiable.
    """
    
    @classmethod
    def generate_attack_vector_justification(
        cls, 
        ctx: VulnerabilityContext, 
        value: str
    ) -> str:
        """Generate justification for Attack Vector metric."""
        if value == "N":
            if ctx.vulnerability_type.lower() in ["sqli", "xss", "ssrf", "csrf"]:
                return f"Vulnerability is accessible over the network via HTTP ({ctx.http_method} {ctx.endpoint})"
            return "Vulnerability is remotely exploitable over the network"
        elif value == "A":
            return "Exploitation requires access to the local network (adjacent network access)"
        elif value == "L":
            return "Exploitation requires local system access"
        elif value == "P":
            return "Exploitation requires physical access to the device"
        return "Attack vector could not be determined"
    
    @classmethod
    def generate_attack_complexity_justification(
        cls, 
        ctx: VulnerabilityContext, 
        value: str
    ) -> str:
        """Generate justification for Attack Complexity metric."""
        if value == "L":
            if ctx.detection_method == "error_based":
                return "Low complexity: Error messages provide direct feedback for exploitation"
            if ctx.exploitation_difficulty == "trivial":
                return "Low complexity: Exploitation is straightforward with no special conditions"
            return "Exploitation requires no special conditions and is reliably reproducible"
        elif value == "H":
            reasons = []
            if ctx.behind_waf:
                reasons.append("WAF evasion required")
            if ctx.requires_specific_conditions:
                reasons.append("specific conditions needed")
            if ctx.exploitation_difficulty == "difficult":
                reasons.append("significant expertise required")
            
            if reasons:
                return f"High complexity: {', '.join(reasons)}"
            return "Exploitation requires specific conditions or has limited success rate"
        return "Attack complexity could not be determined"
    
    @classmethod
    def generate_privileges_required_justification(
        cls, 
        ctx: VulnerabilityContext, 
        value: str
    ) -> str:
        """Generate justification for Privileges Required metric."""
        if value == "N":
            return "No authentication required to exploit this vulnerability"
        elif value == "L":
            return "Exploitation requires a basic user account with standard privileges"
        elif value == "H":
            return f"Exploitation requires administrative or elevated privileges ({ctx.authentication_level})"
        return "Privilege requirements could not be determined"
    
    @classmethod
    def generate_user_interaction_justification(
        cls, 
        ctx: VulnerabilityContext, 
        value: str
    ) -> str:
        """Generate justification for User Interaction metric."""
        vuln_type = ctx.vulnerability_type.lower()
        
        if value == "R":
            if vuln_type.startswith("xss"):
                return "User interaction required: Victim must visit a page containing the malicious script"
            if vuln_type == "csrf":
                return "User interaction required: Victim must submit a form or click a malicious link"
            if ctx.requires_social_engineering:
                return "User interaction required: Social engineering needed to trick victim"
            return "Victim must perform an action for exploitation to succeed"
        elif value == "N":
            if vuln_type in ["sqli", "sql_injection"]:
                return "No user interaction required: Direct database manipulation by attacker"
            if vuln_type in ["ssrf"]:
                return "No user interaction required: Attacker directly triggers server-side requests"
            return "Exploitation is performed directly by the attacker without victim involvement"
        return "User interaction requirement could not be determined"
    
    @classmethod
    def generate_scope_justification(
        cls, 
        ctx: VulnerabilityContext, 
        value: str
    ) -> str:
        """Generate justification for Scope metric."""
        vuln_type = ctx.vulnerability_type.lower()
        
        if value == "C":
            if ctx.can_execute_os_commands:
                return "Scope changed: Vulnerability allows OS command execution, escaping database/application boundary"
            if ctx.can_access_cloud_metadata:
                return "Scope changed: SSRF can access cloud metadata service, compromising infrastructure credentials"
            if vuln_type in ["command_injection", "os_command_injection"]:
                return "Scope changed: Command injection escapes application to operating system"
            return "Impact escapes the vulnerable component's security boundary"
        elif value == "U":
            if vuln_type in ["sqli", "sql_injection"]:
                return "Scope unchanged: Impact limited to database; no OS command execution detected"
            if vuln_type.startswith("xss"):
                return "Scope unchanged: Impact limited to same-origin browser context"
            return "Impact is contained within the vulnerable component"
        return "Scope could not be determined"
    
    @classmethod
    def generate_confidentiality_justification(
        cls, 
        ctx: VulnerabilityContext, 
        value: str
    ) -> str:
        """Generate justification for Confidentiality Impact metric."""
        if value == "H":
            if ctx.data_exposed:
                return f"High confidentiality impact: Attacker can access {', '.join(ctx.data_exposed)}"
            return "Attacker can access all data within the vulnerable component's scope"
        elif value == "L":
            return "Limited information disclosure: Some non-critical data may be exposed"
        elif value == "N":
            return "No confidentiality impact: Vulnerability does not expose data"
        return "Confidentiality impact could not be determined"
    
    @classmethod
    def generate_integrity_justification(
        cls, 
        ctx: VulnerabilityContext, 
        value: str
    ) -> str:
        """Generate justification for Integrity Impact metric."""
        vuln_type = ctx.vulnerability_type.lower()
        
        if value == "H":
            if ctx.data_modifiable:
                return f"High integrity impact: Attacker can modify {', '.join(ctx.data_modifiable)}"
            if vuln_type in ["command_injection"]:
                return "High integrity impact: Attacker can modify any file on the system"
            return "Attacker can modify all data within the vulnerable component's scope"
        elif value == "L":
            if vuln_type.startswith("xss"):
                return "Low integrity impact: Attacker can modify page content in victim's browser"
            return "Limited data modification possible"
        elif value == "N":
            return "No integrity impact: Vulnerability does not allow data modification"
        return "Integrity impact could not be determined"
    
    @classmethod
    def generate_availability_justification(
        cls, 
        ctx: VulnerabilityContext, 
        value: str
    ) -> str:
        """Generate justification for Availability Impact metric."""
        if value == "H":
            if ctx.vulnerability_type.lower() in ["command_injection"]:
                return "High availability impact: Attacker can terminate processes or crash the system"
            return "Complete denial of service is possible"
        elif value == "L":
            return "Partial availability impact: Reduced performance or intermittent disruption"
        elif value == "N":
            return "No availability impact: Vulnerability does not affect service availability"
        return "Availability impact could not be determined"
    
    @classmethod
    def generate_all_justifications(
        cls, 
        ctx: VulnerabilityContext, 
        metrics: Dict[str, str]
    ) -> Dict[str, str]:
        """
        Generate justifications for all metrics.
        
        Args:
            ctx: Vulnerability context
            metrics: Dictionary of metric values {AV, AC, PR, UI, S, C, I, A}
            
        Returns:
            Dictionary mapping metric codes to justification strings
        """
        return {
            "AV": cls.generate_attack_vector_justification(ctx, metrics["AV"]),
            "AC": cls.generate_attack_complexity_justification(ctx, metrics["AC"]),
            "PR": cls.generate_privileges_required_justification(ctx, metrics["PR"]),
            "UI": cls.generate_user_interaction_justification(ctx, metrics["UI"]),
            "S": cls.generate_scope_justification(ctx, metrics["S"]),
            "C": cls.generate_confidentiality_justification(ctx, metrics["C"]),
            "I": cls.generate_integrity_justification(ctx, metrics["I"]),
            "A": cls.generate_availability_justification(ctx, metrics["A"]),
        }
