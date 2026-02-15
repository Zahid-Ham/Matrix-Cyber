import asyncio
import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from config import get_settings
from models.vulnerability import Vulnerability, VulnerabilityType
from agents.base_agent import AgentResult

settings = get_settings()

class ThreatIntelligenceService:
    """
    Service for aggregating real-time threat intelligence from NVD and CISA.
    Computes trend scores and generates AI-driven exploit summaries.
    """
    
    def __init__(self):
        self.cache_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        self.nvd_cache_file = os.path.join(self.cache_dir, "nvd_cache.json")
        self.cisa_cache_file = os.path.join(self.cache_dir, "cisa_cache.json")
        self.cache_ttl = settings.threat_intelligence_cache_ttl_hours * 3600
        
        # Mapping Matrix Vuln Types to NVD keyword searches
        self.vuln_type_keywords = {
            VulnerabilityType.SQL_INJECTION: ["SQL Injection", "SQLi"],
            VulnerabilityType.XSS_DOM: ["DOM XSS", "Cross-site Scripting"],
            VulnerabilityType.XSS_REFLECTED: ["Reflected XSS", "Cross-site Scripting"],
            VulnerabilityType.XSS_STORED: ["Stored XSS", "Cross-site Scripting"],
            VulnerabilityType.OS_COMMAND_INJECTION: ["Command Injection", "RCE"],
            VulnerabilityType.CODE_INJECTION: ["Code Injection", "RCE"],
            VulnerabilityType.CSRF: ["CSRF", "Cross-Site Request Forgery"],
            VulnerabilityType.SSRF: ["SSRF", "Server Side Request Forgery"],
            VulnerabilityType.BROKEN_AUTH: ["Authentication Bypass", "Broken Authentication"],
            VulnerabilityType.API_AUTH_BYPASS: ["API Authentication Bypass"],
        }

    async def _get_cached_data(self, cache_file: str) -> Optional[Dict]:
        """Retrieve data from local cache if valid."""
        if not os.path.exists(cache_file):
            return None
        
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
                timestamp = data.get("timestamp", 0)
                if time.time() - timestamp < self.cache_ttl:
                    return data.get("content")
        except Exception as e:
            print(f"[ThreatIntel] Cache read error: {e}")
        return None

    async def _save_to_cache(self, cache_file: str, content: Any):
        """Save data to local cache."""
        try:
            with open(cache_file, 'w') as f:
                json.dump({
                    "timestamp": time.time(),
                    "content": content
                }, f)
        except Exception as e:
            print(f"[ThreatIntel] Cache write error: {e}")

    async def fetch_nvd_data(self) -> Dict:
        """Fetch last 30 days of vulnerabilities from NVD."""
        cached = await self._get_cached_data(self.nvd_cache_file)
        if cached:
            return cached

        print("[ThreatIntel] Refreshing NVD data...")
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=30)
        
        # NVD v2 API format: 2023-01-01T00:00:00.000
        date_format = "%Y-%m-%dT%H:%M:%S.000"
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start_date.strftime(date_format)}&pubEndDate={end_date.strftime(date_format)}"
        
        headers = {}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                data = response.json()
                await self._save_to_cache(self.nvd_cache_file, data)
                return data
        except Exception as e:
            print(f"[ThreatIntel] NVD Fetch failed: {e}")
            return await self._get_cached_data(self.nvd_cache_file) or {}

    async def fetch_cisa_data(self) -> Dict:
        """Fetch CISA Known Exploited Vulnerabilities Catalog."""
        # 1. Check if a local file is configured and exists
        if settings.cisa_kev_file_path and os.path.exists(settings.cisa_kev_file_path):
            print(f"[ThreatIntel] Using local CISA data from {settings.cisa_kev_file_path}")
            try:
                with open(settings.cisa_kev_file_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[ThreatIntel] Failed to read local CISA file: {e}")

        # 2. Check cache
        cached = await self._get_cached_data(self.cisa_cache_file)
        if cached:
            return cached

        # 3. Fetch from remote
        print("[ThreatIntel] Refreshing CISA data from remote...")
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                await self._save_to_cache(self.cisa_cache_file, data)
                return data
        except Exception as e:
            print(f"[ThreatIntel] CISA Fetch failed: {e}")
            return await self._get_cached_data(self.cisa_cache_file) or {}

    def compute_trend_score(self, vuln_type: VulnerabilityType, nvd_data: Dict, cisa_data: Dict) -> Dict:
        """
        Determine trending status and score for a vulnerability type.
        """
        keywords = self.vuln_type_keywords.get(vuln_type, [vuln_type.value.replace('_', ' ')])
        
        # Filter NVD for matches
        vulnerabilities = nvd_data.get("vulnerabilities", [])
        matches = []
        cvss_scores = []
        
        for v in vulnerabilities:
            cve = v.get("cve", {})
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            
            if any(kw.lower() in desc.lower() for kw in keywords):
                matches.append(cve.get("id"))
                # Extract CVSS
                metrics = cve.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
                if cvss_v3:
                    cvss_scores.append(cvss_v3[0].get("cvssData", {}).get("baseScore", 0))

        # Check CISA exploitation
        cisa_vulns = cisa_data.get("vulnerabilities", [])
        exploited_count = 0
        for cv in cisa_vulns:
            v_desc = cv.get("shortDescription", "")
            if any(kw.lower() in v_desc.lower() for kw in keywords):
                exploited_count += 1

        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        freq = len(matches)
        
        # Weighted Scoring Model
        # frequency (0-40) + avg_cvss (0-30) + exploited_presence (0-30)
        norm_freq = min(freq * 2, 40) 
        norm_cvss = (avg_cvss / 10) * 30
        norm_exploited = 30 if exploited_count > 0 else 0
        
        trend_score = int(norm_freq + norm_cvss + norm_exploited)
        
        # Activity Level
        if trend_score > 80: activity = "Critical"
        elif trend_score > 60: activity = "High"
        elif trend_score > 40: activity = "Medium"
        else: activity = "Low"

        return {
            "trend_score": trend_score,
            "avg_cvss": round(avg_cvss, 1),
            "actively_exploited": exploited_count > 0,
            "activity_level": activity,
            "disclosure_count_30d": freq
        }

    async def get_threat_intelligence(self, vuln: Vulnerability) -> Dict:
        """Aggregate data and generate AI analysis for a specific vulnerability finding."""
        nvd_data = await self.fetch_nvd_data()
        cisa_data = await self.fetch_cisa_data()
        
        metrics = self.compute_trend_score(vuln.vulnerability_type, nvd_data, cisa_data)
        
        # Call Groq for deep analysis
        ai_analysis = await self._generate_ai_threat_analysis(vuln, metrics)
        
        result = {
            **metrics,
            **ai_analysis,
            "data_sources": ["NVD", "CISA", "Groq AI"]
        }
        
        return result

    async def _generate_ai_threat_analysis(self, vuln: Vulnerability, metrics: Dict) -> Dict:
        """Generate structured JSON analysis using Groq LLM."""
        
        prompt = f"""
        You are a Threat Intelligence Expert. Analyze the following detected vulnerability and its current threat landscape metrics.
        
        Vulnerability Type: {vuln.vulnerability_type}
        Detection Title: {vuln.title}
        Vulnerable Code Snippet: {vuln.evidence}
        Trend Score: {metrics['trend_score']}/100
        Exploitation Status: {"Actively Exploited (CISA)" if metrics['actively_exploited'] else "No Active Exploitation Reported"}
        Average CVSS: {metrics['avg_cvss']}
        
        Generate a deep technical analysis in JSON format:
        {{
          "attack_summary": "Concise technical summary of the attack vector",
          "why_trending": "Explain why this specific attack type is currently trending based on disclosures and real-world exploitation",
          "real_world_exploit_flow": [
              "Step 1: Description of initial reconnaissance/vector",
              "Step 2: Description of the application processing the malicious input",
              "Step 3: Description of the execution point or logic failure",
              "Impact: Technical result of successful exploitation"
          ],
          "business_impact": "How this affects business operations and data integrity",
          "technical_impact": "Direct technical consequences (e.g., identity theft, DB leak, RCE)"
        }}
        
        Ensure "real_world_exploit_flow" is a step-by-step sequence that matches the logic found in the code snippet.
        Output ONLY the JSON object.
        """
        
        try:
            # Note: We need a reliable way to call Groq. Using the shared utility if it exists.
            # For this implementation, I'll use a simple httpx call directly if necessary, 
            # but I'll try to find an existing orchestrator/agent utility.
            # Based on the context, I'll use a placeholder or the actual query_groq if I can find its signature.
            
            # For now, I'll implement a fallback/direct call logic or use an existing one.
            # Looking at backend/agents/base_agent.py might help.
            
            # I will check backend/agents/base_agent.py first.
            return await self._call_groq(prompt)
        except Exception as e:
            print(f"[ThreatIntel] AI Analysis failed: {e}")
            return {
                "attack_summary": "Analysis unavailable",
                "why_trending": "N/A",
                "real_world_exploit_flow": ["N/A"],
                "business_impact": "N/A",
                "technical_impact": "N/A"
            }

    async def _call_groq(self, prompt: str) -> Dict:
        """Direct call to Groq API for structured output."""
        url = "https://api.groq.com/openai/v1/chat/completions"
        api_key = settings.groq_api_key_scanner or os.getenv("GROQ_API_KEY")
        
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": settings.groq_model_scanner_primary,
            "messages": [
                {"role": "system", "content": "You are a lead security researcher providing structured threat intelligence."},
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            res_json = response.json()
            content = res_json["choices"][0]["message"]["content"]
            return json.loads(content)

# Singleton instance
threat_intel_service = ThreatIntelligenceService()
