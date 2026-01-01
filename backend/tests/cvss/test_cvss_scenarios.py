"""
SQL Injection Agent - CVSS Validation Tests

Tests to ensure SQL injection agent produces correct CVSS scores
for various scenarios.
"""
import pytest
from typing import Dict, Any

pytestmark = pytest.mark.cvss


class TestSQLAgentCVSSScenarios:
    """Test CVSS scores for SQL injection scenarios."""
    
    @pytest.mark.asyncio
    async def test_unauthenticated_error_based_cvss(
        self,
        sql_agent,
        cvss_scenarios,
        cvss_validator
    ):
        """
        Test: Unauthenticated error-based SQL injection
        Expected: CVSS 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
        """
        scenario = cvss_scenarios["sqli_unauthenticated_error_based"]
        
        # Create vulnerability context matching the scenario
        from scoring.vulnerability_context import VulnerabilityContext
        context = VulnerabilityContext(
            vulnerability_type=scenario["vulnerability_type"],
            detection_method=scenario["detection_method"],
            endpoint="/api/products",
            parameter="id",
            http_method="GET",
            requires_authentication=scenario["requires_authentication"],
            authentication_level=scenario["authentication_level"],
            network_accessible=scenario["network_accessible"],
            requires_user_interaction=scenario["requires_user_interaction"],
            escapes_security_boundary=scenario["escapes_security_boundary"],
            data_exposed=scenario["data_exposed"],
            data_modifiable=["database"],
            additional_context={"can_delete_data": True},
            payload_succeeded=True
        )
        
        # Create result using agent's create_result method
        result = sql_agent.create_result(
            vulnerability_type="SQL_INJECTION",
            is_vulnerable=True,
            severity="CRITICAL",
            confidence=80.0,
            url="http://test.local/api/products",
            parameter="id",
            method="GET",
            title="SQL Injection (Error-Based) in 'id'",
            description="Error-based SQL injection detected",
            evidence="MySQL error: You have an error in your SQL syntax",
            vulnerability_context=context
        )
        
        # Validate CVSS score
        cvss_validator["assert_metrics"](result, {
            "score": scenario["expected_cvss"],
            "vector": scenario["expected_vector"],
            "scope_changed": False,
            "pr": "N",
            "ui": "N"
        })
    
    @pytest.mark.asyncio
    async def test_xp_cmdshell_scope_changed_cvss(
        self,
        sql_agent,
        cvss_scenarios,
        cvss_validator
    ):
        """
        Test: SQL injection with xp_cmdshell (OS command execution)
        Expected: CVSS 10.0 with Scope:Changed
        
        This is CRITICAL: xp_cmdshell escapes database sandbox to OS
        """
        scenario = cvss_scenarios["sqli_xp_cmdshell_scope_changed"]
        
        from scoring.vulnerability_context import VulnerabilityContext
        context = VulnerabilityContext(
            vulnerability_type=scenario["vulnerability_type"],
            detection_method=scenario["detection_method"],
            endpoint="/api/products",
            parameter="id",
            http_method="GET",
            requires_authentication=scenario["requires_authentication"],
            authentication_level=scenario["authentication_level"],
            network_accessible=scenario["network_accessible"],
            requires_user_interaction=scenario["requires_user_interaction"],
            # CRITICAL: Scope:Changed flags
            escapes_security_boundary=scenario["escapes_security_boundary"],
            can_execute_os_commands=scenario["can_execute_os_commands"],
            data_exposed=scenario["data_exposed"],
            data_modifiable=["database", "filesystem"],  # xp_cmdshell can modify OS
            payload_succeeded=True,
            target_technology="MSSQL"
        )
        
        result = sql_agent.create_result(
            vulnerability_type="SQL_INJECTION",
            is_vulnerable=True,
            severity="CRITICAL",
            confidence=95.0,
            url="http://test.local/api/products",
            parameter="id",
            method="GET",
            title="SQL Injection with OS Command Execution",
            description="SQL injection allows xp_cmdshell execution",
            evidence="Successfully executed: xp_cmdshell 'whoami'",
            vulnerability_context=context
        )
        
        # Validate Scope:Changed is detected
        cvss_validator["validate_scope"](context, should_be_changed=True)
        
        # Validate CVSS 10.0
        cvss_validator["assert_metrics"](result, {
            "score": scenario["expected_cvss"],
            "scope_changed": True,
            "pr": "N",
            "ui": "N"
        })
    
    @pytest.mark.asyncio
    async def test_authenticated_time_based_cvss(
        self,
        sql_agent,
        cvss_scenarios,
        cvss_validator
    ):
        """
        Test: Authenticated time-based SQL injection
        Expected: CVSS 8.1 (lower due to PR:L)
        """
        scenario = cvss_scenarios["sqli_authenticated_time_based"]
        
        from scoring.vulnerability_context import VulnerabilityContext
        context = VulnerabilityContext(
            vulnerability_type=scenario["vulnerability_type"],
            detection_method=scenario["detection_method"],
            endpoint="/api/user/profile",
            parameter="user_id",
            http_method="GET",
            requires_authentication=scenario["requires_authentication"],
            authentication_level=scenario["authentication_level"],
            network_accessible=scenario["network_accessible"],
            requires_user_interaction=scenario["requires_user_interaction"],
            escapes_security_boundary=scenario["escapes_security_boundary"],
            data_exposed=scenario["data_exposed"],
            data_modifiable=["database"],
            payload_succeeded=True
        )
        
        result = sql_agent.create_result(
            vulnerability_type="SQL_INJECTION",
            is_vulnerable=True,
            severity="CRITICAL",
            confidence=90.0,
            url="http://test.local/api/user/profile",
            parameter="user_id",
            method="GET",
            title="SQL Injection (Time-Based Blind) in 'user_id'",
            description="Time-based blind SQL injection on authenticated endpoint",
            evidence="Response delayed by 5 seconds with SLEEP() payload",
            vulnerability_context=context
        )
        
        # Validate PR:L (low privilege / user account)
        cvss_validator["validate_pr"](context, expected_pr="L")
        
        # Validate score reflects authentication requirement
        cvss_validator["assert_metrics"](result, {
            "score": scenario["expected_cvss"],
            "scope_changed": False,
            "pr": "L",
            "ui": "N"
        })
    
    @pytest.mark.asyncio
    async def test_admin_only_sqli_cvss(
        self,
        sql_agent,
        cvss_scenarios,
        cvss_validator
    ):
        """
        Test: SQL injection on admin-only endpoint
        Expected: CVSS 7.2 (PR:H reduces score significantly)
        """
        scenario = cvss_scenarios["sqli_admin_only"]
        
        from scoring.vulnerability_context import VulnerabilityContext
        context = VulnerabilityContext(
            vulnerability_type=scenario["vulnerability_type"],
            detection_method=scenario["detection_method"],
            endpoint="/admin/users",
            parameter="id",
            http_method="GET",
            requires_authentication=scenario["requires_authentication"],
            authentication_level=scenario["authentication_level"],  # "high" or "admin"
            network_accessible=scenario["network_accessible"],
            requires_user_interaction=scenario["requires_user_interaction"],
            escapes_security_boundary=scenario["escapes_security_boundary"],
            data_exposed=scenario["data_exposed"],
            data_modifiable=["database"],
            additional_context={"can_delete_data": True},
            payload_succeeded=True
        )
        
        result = sql_agent.create_result(
            vulnerability_type="SQL_INJECTION",
            is_vulnerable=True,
            severity="HIGH",  # Severity may be HIGH instead of CRITICAL due to admin requirement
            confidence=85.0,
            url="http://test.local/admin/users",
            parameter="id",
            method="GET",
            title="SQL Injection in Admin Panel",
            description="SQL injection on admin-only endpoint",
            evidence="SQL error in admin interface",
            vulnerability_context=context
        )
        
        # Validate PR:H (high privilege / admin account)
        cvss_validator["validate_pr"](context, expected_pr="H")
        
        # Validate reduced score
        cvss_validator["assert_metrics"](result, {
            "score": scenario["expected_cvss"],
            "scope_changed": False,
            "pr": "H",
            "ui": "N"
        })


class TestCommandInjectionCVSS:
    """Test that command injection ALWAYS has Scope:Changed."""
    
    @pytest.mark.asyncio
    async def test_command_injection_always_scope_changed(
        self,
        command_injection_agent,
        cvss_scenarios,
        cvss_validator
    ):
        """
        CRITICAL TEST: Command injection MUST ALWAYS have Scope:Changed
        
        Rationale: Command injection escapes the application sandbox
        to execute OS-level commands. This is ALWAYS a scope change.
        """
        scenario = cvss_scenarios["command_injection_unauthenticated"]
        
        from scoring.vulnerability_context import VulnerabilityContext
        context = VulnerabilityContext(
            vulnerability_type=scenario["vulnerability_type"],
            detection_method=scenario["detection_method"],
            endpoint="/api/ping",
            parameter="host",
            http_method="GET",
            requires_authentication=scenario["requires_authentication"],
            authentication_level=scenario["authentication_level"],
            network_accessible=scenario["network_accessible"],
            requires_user_interaction=scenario["requires_user_interaction"],
            # CRITICAL: ALWAYS Scope:Changed for command injection
            escapes_security_boundary=scenario["escapes_security_boundary"],
            can_execute_os_commands=scenario["can_execute_os_commands"],
            data_exposed=scenario["data_exposed"],
            data_modifiable=["filesystem", "database", "configuration"],  # Command injection can modify EVERYTHING
            service_disruption_possible=True,
            payload_succeeded=True
        )
        
        # Validate Scope:Changed markers
        assert context.escapes_security_boundary == True, \
            "Command injection MUST have escapes_security_boundary=True"
        assert context.can_execute_os_commands == True, \
            "Command injection MUST have can_execute_os_commands=True"
        
        result = command_injection_agent.create_result(
            vulnerability_type="OS_COMMAND_INJECTION",
            is_vulnerable=True,
            severity="CRITICAL",
            confidence=95.0,
            url="http://test.local/api/ping",
            parameter="host",
            method="GET",
            title="OS Command Injection in 'host'",
            description="Command injection allows arbitrary OS command execution",
            evidence="uid=33(www-data) gid=33(www-data) groups=33(www-data)",
            vulnerability_context=context
        )
        
        # Validate Scope:Changed in CVSS vector
        assert "S:C" in result.cvss_vector, \
            f"Command injection MUST have Scope:Changed. Vector: {result.cvss_vector}"
        
        # Validate CVSS 10.0
        cvss_validator["assert_metrics"](result, {
            "score": 10.0,
            "scope_changed": True,
            "pr": "N",
            "ui": "N"
        })
