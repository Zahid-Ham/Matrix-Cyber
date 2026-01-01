"""
Orchestrator Integration Tests
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from agents.orchestrator import AgentOrchestrator, AgentNames, OrchestratorConfig
from agents.base_agent import BaseSecurityAgent, AgentResult
from core.scan_context import ScanContext, AgentPhase
from models.vulnerability import Severity, VulnerabilityType

# Mock agents for testing
class MockAgent(BaseSecurityAgent):
    agent_name = "mock_agent"
    async def scan(self, target_url, endpoints, **kwargs):
        return []

@pytest.fixture
def orchestrator():
    orchestrator = AgentOrchestrator()
    # Replace default agents with mocks or specific configurations if needed
    return orchestrator

class TestOrchestratorDependencies:
    """Test agent dependency resolution and execution order."""

    @pytest.mark.asyncio
    async def test_dependency_resolution(self, orchestrator):
        """Verify that agents run in correct phase-based order."""
        # We'll mock the internal _run_agent call to track execution order
        execution_order = []
        
        async def mock_run_agent(agent, target_url, endpoints, tech_stack):
            execution_order.append(agent.agent_name)
            return []

        # Selective agents to speed up test
        agents_enabled = [AgentNames.AUTH, AgentNames.SQL_INJECTION]
        
        with patch.object(orchestrator, '_run_agent', side_effect=mock_run_agent):
            await orchestrator.run_scan(
                target_url="http://target.local",
                agents_enabled=agents_enabled,
                endpoints=[{"url": "http://target.local", "method": "GET"}]
            )
            
        # AUTH (DISCOVERY) must run before SQL_INJECTION (EXPLOITATION)
        auth_idx = execution_order.index(AgentNames.AUTH)
        sqli_idx = execution_order.index(AgentNames.SQL_INJECTION)
        assert auth_idx < sqli_idx
        assert AgentNames.GITHUB not in execution_order # Not in enabled list

    @pytest.mark.asyncio
    async def test_selective_execution(self, orchestrator):
        """Verify only enabled agents are executed."""
        with patch.object(orchestrator, '_run_agent', return_value=[]) as mock_exec:
            await orchestrator.run_scan(
                target_url="http://target.local",
                agents_enabled=[AgentNames.XSS],
                endpoints=[{"url": "http://target.local", "method": "GET"}]
            )
            
            # Should only call XSS
            called_agents = [call.args[0].agent_name for call in mock_exec.call_args_list]
            assert AgentNames.XSS in called_agents
            assert len(called_agents) == 1

    @pytest.mark.asyncio
    async def test_agent_failure_propagation(self, orchestrator):
        """Verify that an agent failure does not crash the entire scan."""
        async def failing_scan(*args, **kwargs):
            raise Exception("Agent crashed!")

        # Patch _run_agent to simulate failure
        with patch.object(orchestrator, '_run_agent', side_effect=failing_scan):
            results = await orchestrator.run_scan(
                target_url="http://target.local",
                agents_enabled=[AgentNames.AUTH],
                endpoints=[{"url": "http://target.local", "method": "GET"}]
            )
            
            assert len(orchestrator.failed_agents) == 1
            assert orchestrator.failed_agents[0]['agent'] == AgentNames.AUTH

class TestOrchestratorContextSharing:
    """Test shared context management between agents."""

    @pytest.mark.asyncio
    async def test_context_propagation_auth_to_sqli(self, orchestrator):
        """Verify context updates from one agent are visible to subsequent ones."""
        
        async def mock_auth_scan(target_url, endpoints, **kwargs):
            # Simulate finding credentials
            orchestrator.scan_context.add_credential("admin", "password123", "auth_agent", "http://login")
            return []

        async def mock_sqli_scan(target_url, endpoints, **kwargs):
            # Verify we can see the credentials in scan_context
            assert len(orchestrator.scan_context.discovered_credentials) > 0
            assert orchestrator.scan_context.discovered_credentials[0].username == "admin"
            return []

        # Setup mock behavior
        orchestrator.agents[AgentNames.AUTH].scan = mock_auth_scan
        orchestrator.agents[AgentNames.SQL_INJECTION].scan = mock_sqli_scan
        
        await orchestrator.run_scan(
            target_url="http://target.local",
            agents_enabled=[AgentNames.AUTH, AgentNames.SQL_INJECTION],
            endpoints=[{"url": "http://target.local", "method": "GET"}]
        )

class TestOrchestratorIntelligenceLayer:
    """Test deduplication and filtering in the analysis phase."""

    def test_deduplication_similar_findings(self, orchestrator):
        """Verify that similar findings from different agents are merged."""
        finding1 = AgentResult(
            agent_name="xss_agent",
            vulnerability_type=VulnerabilityType.XSS_REFLECTED,
            is_vulnerable=True,
            severity=Severity.HIGH,
            confidence=90.0,
            url="http://target.local/page?q=vulnerable",
            method="GET",
            title="Reflected XSS",
            evidence="alert(1)",
            description="XSS found"
        )
        
        finding2 = AgentResult(
            agent_name="xss_agent",
            vulnerability_type=VulnerabilityType.XSS_REFLECTED,
            is_vulnerable=True,
            severity=Severity.HIGH,
            confidence=85.0,
            url="http://target.local/page?q=vulnerable", # Same URL/Param
            method="GET",
            title="Cross-Site Scripting",
            evidence="alert(1)",
            description="Another XSS found"
        )
        
        orchestrator.results = [finding1, finding2]
        
        # Manually trigger deduplication
        deduplicated = orchestrator._deduplicate_results_similarity(orchestrator.results)
        
        assert len(deduplicated) == 1
        assert "Reflected XSS" in deduplicated[0].title or "Cross-Site Scripting" in deduplicated[0].title

    def test_false_positive_filtering(self, orchestrator):
        """Verify that findings with false positive indicators are marked."""
        real_finding = AgentResult(
            agent_name="sql_agent",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            is_vulnerable=True,
            severity=Severity.HIGH,
            confidence=95.0,
            url="http://target.local/vuln",
            title="Real SQLi",
            evidence="syntax error at or near \"'\"",
            description="Verified SQLi"
        )
        
        fp_finding = AgentResult(
            agent_name="xss_agent",
            vulnerability_type=VulnerabilityType.XSS_REFLECTED,
            is_vulnerable=True,
            severity=Severity.HIGH,
            confidence=80.0,
            url="http://target.local/fp",
            title="False Positive XSS",
            evidence="<script>alert(1)</script>",
            ai_analysis="This finding is likely a placeholder or example value.", # Trigger keyword
            description="Actually not vulnerable"
        )
        
        orchestrator.results = [real_finding, fp_finding]
        results = orchestrator._filter_false_positives(orchestrator.results)
        
        assert results[0].is_false_positive is False
        assert results[1].is_false_positive is True
        assert results[1].final_verdict == "FALSE_POSITIVE"
        assert results[1].action_required is False
