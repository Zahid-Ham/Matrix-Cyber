
import asyncio
import os
import sys
import unittest
from unittest.mock import MagicMock, patch
import logging
logging.basicConfig(level=logging.ERROR)

# Add parent directory to path (Matrix root)
root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, root_dir)
# Add backend directory to path (for 'core' imports)
sys.path.insert(0, os.path.join(root_dir, 'backend'))

from agents.github_agent import GithubSecurityAgent
from models.vulnerability import VulnerabilityType, Severity

SAMPLE_VULNERABLE_CODE = """
const express = require('express');
const app = express();

app.get("/test", (req, res) => {
  // Rule: Taint Source (req.query) -> Taint Sink (eval)
  eval(req.query.code);
});

app.post("/login", (req, res) => {
    const email = req.body.email;
    const query = "SELECT * FROM users WHERE email = '" + email + "'";
    sequelize.query(query);
});
"""

class TestNodeTaintAnalysis(unittest.TestCase):
    def setUp(self):
        self.agent = GithubSecurityAgent()
        # Mock semaphore to avoid asyncio loop mismatch issues in tests
        self.agent._ai_semaphore = MagicMock()
        self.agent._ai_semaphore.__aenter__.return_value = None
        self.agent._ai_semaphore.__aexit__.return_value = None

    @patch('agents.github_agent.repo_generate')
    def test_taint_prompt_injection(self, mock_repo_generate):
        print("\n--- Testing Taint Analysis Prompt Injection ---")
        
        # Mock AI response
        mock_repo_generate.return_value = {
            "content": '```json\n{"vulnerabilities": [{"file": "server.js", "type": "code_injection", "severity": "CRITICAL", "line": 6, "title": "Remote Code Execution via eval", "description": "User input from req.query.code flows into eval() without sanitization.", "fix": "Avoid eval() entirely.", "confidence": 95}]}\n```'
        }

        # Create a batch with the sample code
        batch = [{
            "path": "server.js",
            "content": SAMPLE_VULNERABLE_CODE
        }]

        # Run analysis (mocked)
        results = asyncio.run(self.agent._analyze_batch_single_call(
            batch, "test_owner", "test_repo", "main"
        ))

        # 1. Verify Prompt Construction
        call_args = mock_repo_generate.call_args
        prompt_sent = call_args.kwargs['prompt']
        
        print("Verifying 'TAINT ANALYSIS INSTRUCTION' in prompt...")
        if "TAINT ANALYSIS INSTRUCTION (Node.js/Express):" in prompt_sent:
            print("PASS: Taint instructions found in prompt.")
        else:
            self.fail("FAIL: Taint instructions NOT found in prompt.")

        print("Verifying Source/Sink guidelines...")
        if "Identify SINKS (Execution): sequelize.query, exec, eval" in prompt_sent:
            print("PASS: Specific sinks listed in prompt.")
        else:
            self.fail("FAIL: Specific sinks missing from prompt.")

        # 2. Verify Result Parsing
        print("\nVerifying Result Parsing...")
        self.assertEqual(len(results), 1)
        vuln = results[0]
        print(f"Detected: {vuln.title} (Severity: {vuln.severity})")
        
        if vuln.severity in [Severity.CRITICAL, Severity.HIGH] and "eval" in vuln.title:
            print(f"PASS: Successfully parsed vuln finding (Severity: {vuln.severity}).")
        else:
            self.fail(f"FAIL: Unexpected parsing result: {vuln}")

if __name__ == '__main__':
    unittest.main()
