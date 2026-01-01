"""
Performance and Stress Tests for the AgentOrchestrator.
Measurements are taken for various endpoint loads to identify bottlenecks and scalability.
"""
import pytest
import asyncio
import time
import json
import os
from typing import List, Dict, Any
from unittest.mock import patch, MagicMock, AsyncMock

from agents.orchestrator import AgentOrchestrator, AgentNames
from agents.base_agent import AgentResult
from models.vulnerability import Severity, VulnerabilityType

class PerformanceMetrics:
    def __init__(self):
        self.results = []

    def add_result(self, name: str, endpoint_count: int, duration: float):
        self.results.append({
            "scenario": name,
            "endpoint_count": endpoint_count,
            "duration_seconds": round(duration, 3),
            "per_endpoint_ms": round((duration / endpoint_count) * 1000, 3) if endpoint_count > 0 else 0
        })

    def save(self, filepath: str):
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=4)

metrics = PerformanceMetrics()

@pytest.fixture
def orchestrator():
    orchestrator = AgentOrchestrator()
    return orchestrator

def generate_endpoints(count: int) -> List[Dict[str, Any]]:
    return [
        {"url": f"http://target.local/api/v1/resource/{i}", "method": "GET", "params": {"id": i}}
        for i in range(count)
    ]

async def mock_agent_scan(agent, target_url, endpoints, technology_stack):
    # Simulate a small processing delay per endpoint
    # In a real scan, agents spend time on HTTP requests and AI analysis
    # We mock it as 1ms per endpoint to test orchestrator overhead
    await asyncio.sleep(len(endpoints) * 0.001) 
    return []

@pytest.mark.asyncio
async def test_performance_baseline(orchestrator):
    """Measure baseline overhead with 1 endpoint."""
    endpoints = generate_endpoints(1)
    
    start_time = time.perf_counter()
    with patch.object(orchestrator, '_run_agent', side_effect=mock_agent_scan):
        await orchestrator.run_scan(
            target_url="http://target.local",
            agents_enabled=[AgentNames.AUTH, AgentNames.SQL_INJECTION, AgentNames.XSS],
            endpoints=endpoints,
            technology_stack=["Python"]
        )
    duration = time.perf_counter() - start_time
    metrics.add_result("baseline", 1, duration)
    assert duration < 5.0 # Baseline should be very fast

@pytest.mark.asyncio
async def test_performance_typical(orchestrator):
    """Measure performance with 10 endpoints."""
    endpoints = generate_endpoints(10)
    
    start_time = time.perf_counter()
    with patch.object(orchestrator, '_run_agent', side_effect=mock_agent_scan):
        await orchestrator.run_scan(
            target_url="http://target.local",
            agents_enabled=[AgentNames.AUTH, AgentNames.SQL_INJECTION, AgentNames.XSS],
            endpoints=endpoints,
            technology_stack=["Python"]
        )
    duration = time.perf_counter() - start_time
    metrics.add_result("typical", 10, duration)

@pytest.mark.asyncio
async def test_performance_stress(orchestrator):
    """Measure performance with 100 endpoints."""
    endpoints = generate_endpoints(100)
    
    start_time = time.perf_counter()
    with patch.object(orchestrator, '_run_agent', side_effect=mock_agent_scan):
        await orchestrator.run_scan(
            target_url="http://target.local",
            agents_enabled=[AgentNames.AUTH, AgentNames.SQL_INJECTION, AgentNames.XSS],
            endpoints=endpoints,
            technology_stack=["Python"]
        )
    duration = time.perf_counter() - start_time
    metrics.add_result("stress", 100, duration)

@pytest.mark.asyncio
async def test_performance_extreme(orchestrator):
    """Measure performance with 1000 endpoints."""
    endpoints = generate_endpoints(1000)
    
    start_time = time.perf_counter()
    with patch.object(orchestrator, '_run_agent', side_effect=mock_agent_scan):
        await orchestrator.run_scan(
            target_url="http://target.local",
            agents_enabled=[AgentNames.AUTH, AgentNames.SQL_INJECTION, AgentNames.XSS],
            endpoints=endpoints,
            technology_stack=["Python"]
        )
    duration = time.perf_counter() - start_time
    metrics.add_result("extreme", 1000, duration)

def test_save_results():
    """Final test to save results to a JSON file."""
    # This is a bit of a hack to run after all async tests
    # In a real setup, we might use a session-scoped teardown
    metrics_path = os.path.join(os.getcwd(), "benchmark_results.json")
    metrics.save(metrics_path)
    print(f"\nPerformance results saved to {metrics_path}")
