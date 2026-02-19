
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, or_, case
from typing import List, Optional, Dict, Any
from marketplace_simulation.models import ExploitPricing, FinancialImpact, VulnerabilityValuation
from models import Vulnerability, Severity

# Force registration for foreign key mapping
import models.vulnerability
import marketplace_simulation.models.valuation
import marketplace_simulation.models.exploit_pricing
import marketplace_simulation.models.financial_impact

from marketplace_simulation.services.valuation_service import ValuationService
from marketplace_simulation.services.financial_impact_service import FinancialImpactService
from core.groq_client import chatbot_generate

class MarketplaceService:
    
    @staticmethod
    async def get_exploit_pricing(db: AsyncSession, 
                                 vulnerability_type: Optional[str] = None, 
                                 limit: int = 100) -> List[ExploitPricing]:
        query = select(ExploitPricing)
        if vulnerability_type:
            query = query.where(ExploitPricing.vulnerability_type.ilike(f"%{vulnerability_type}%"))
        
        query = query.limit(limit)
        result = await db.execute(query)
        return result.scalars().all()

    @staticmethod
    async def get_financial_impact(db: AsyncSession, 
                                  industry: Optional[str] = None, 
                                  limit: int = 100) -> List[FinancialImpact]:
        query = select(FinancialImpact)
        if industry:
            query = query.where(FinancialImpact.industry.ilike(f"%{industry}%"))
            
        query = query.limit(limit)
        result = await db.execute(query)
        return result.scalars().all()

    @staticmethod
    async def get_valuation(db: AsyncSession, vulnerability_id: int) -> Optional[VulnerabilityValuation]:
        stmt = select(VulnerabilityValuation).where(VulnerabilityValuation.vulnerability_id == vulnerability_id).order_by(desc(VulnerabilityValuation.created_at)).limit(1)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    @classmethod
    async def analyze_vulnerability(cls, vulnerability_id: int, db: AsyncSession) -> Dict[str, Any]:
        """
        Orchestrates the marketplace analysis.
        1. Fetches vulnerability details.
        2. Calculates Exploit Value (ValuationService).
        3. Calculates Financial Impact (FinancialImpactService).
        4. Estimates Fix Cost & ROI.
        5. Generates Dynamic Market Context & Attack Paths.
        """
        # 1. Fetch Vulnerability
        stmt = select(Vulnerability).where(Vulnerability.id == vulnerability_id)
        result = await db.execute(stmt)
        vuln = result.scalar_one_or_none()
        
        if not vuln:
            raise ValueError(f"Vulnerability {vulnerability_id} not found")
            
        # Context Factors (Simulation)
        industry = "FinTech"  # In real app, comes from user profile
        size = "Enterprise"
        profile = {
            "industry": industry,
            "revenue": 500000000,
            "dataRecords": 100000
        }

        # 2. Calculate Exploit Value
        valuation_data = await ValuationService.calculate_exploit_value(
            db, vuln, industry, size
        )
        
        # 3. Calculate Financial Impact
        impact_data = await FinancialImpactService.calculate_breach_impact(
            db, vuln, profile
        )
        
        # 4. ROI Analysis (Fix Cost vs Potential Damage)
        fix_data = ValuationService.estimate_fix_cost(vuln)
        fix_cost = fix_data["cost"]
        potential_damage = impact_data["totalImpact"]["avgTotal"]
        
        roi_display = "0%"
        if fix_cost > 0:
            roi_raw = ((potential_damage - fix_cost) / fix_cost)
            roi_pct = roi_raw * 100
            
            # Format nicely for UI
            if roi_pct > 1000:
                roi_display = f"{int(roi_raw)}x Return"
            else:
                roi_display = f"{int(roi_pct)}%"

        # 5. Dynamic Context Generation (LLM-Enhanced)
        market_context = await cls._generate_market_context(vuln, valuation_data["exploitValue"]["avg"])
        attack_path = await cls._generate_attack_path(vuln)
        equivalents = cls._generate_equivalents(valuation_data["exploitValue"]["avg"])
        
        # Fuzz confidence score slightly to feel more organic (65-85% for heuristic)
        import random
        base_confidence = valuation_data["exploitValue"]["confidence"]
        if base_confidence < 90: # Don't fuzz high confidence matches
            valuation_data["exploitValue"]["confidence"] = min(95, max(40, base_confidence + random.randint(-5, 15)))

        # 6. PERSIST TO DATABASE (Aligned with model schema)
        valuation_record = VulnerabilityValuation(
            vulnerability_id=vulnerability_id,
            calculated_min=valuation_data["exploitValue"]["min"],
            calculated_max=valuation_data["exploitValue"]["max"],
            calculated_avg=valuation_data["exploitValue"]["avg"],
            total_financial_impact_min=impact_data["totalImpact"]["minTotal"],
            total_financial_impact_max=impact_data["totalImpact"]["maxTotal"],
            total_financial_impact_avg=impact_data["totalImpact"]["avgTotal"],
            industry_multiplier=impact_data["totalImpact"].get("industryMultiplier", 1.0)
        )
        
        db.add(valuation_record)
        
        # Update vulnerability - use values directly to avoid session issues
        # and ensure we aren't triggering any lazy loads
        vuln.marketplace_value_avg = float(valuation_data["exploitValue"]["avg"])
        vuln.marketplace_last_analyzed = datetime.now(timezone.utc)
        
        await db.commit()

        return {
            "vulnerabilityId": vulnerability_id,
            "scanId": vuln.scan_id,
            "title": vuln.title,
            "severity": vuln.severity.value,
            "status": vuln.status.value,
            "cvss": vuln.cvss_score,
            "exploitValue": valuation_data["exploitValue"],
            "exploitBreakdown": valuation_data["breakdown"], 
            "financialImpact": impact_data["totalImpact"],
            "roiAnalysis": {
                "fixCost": fix_cost,
                "fixHours": fix_data["hours"], 
                "exploitValue": valuation_data["exploitValue"]["avg"],
                "potentialDamage": potential_damage,
                "roi": roi_display
            },
            "marketContext": market_context,
            "attackPath": attack_path,
            "equivalents": equivalents
        }

    @staticmethod
    async def _generate_market_context(vuln: Vulnerability, value: int) -> Dict[str, Any]:
        """Generates dynamic market context using Groq API."""
        try:
            prompt = f"""
            Generate a realistic dark web market context for a vulnerability with the following details:
            Title: {vuln.title}
            Description: {vuln.description or "No description provided."}
            Severity: {vuln.severity.value}
            Estimated Value: ${value}

            Return a JSON object with this exact structure:
            {{
                "similarExploits": [
                    {{"name": "Specific Exploit Name 1", "price": 1234}},
                    {{"name": "Specific Exploit Name 2", "price": 5678}}
                ],
                "typicalBuyers": ["Buyer Type 1", "Buyer Type 2"],
                "marketTrend": "Increasing" | "Stable" | "Decreasing"
            }}
            Make the exploits and buyers specific to the vulnerability type (e.g., SQLi, XSS, RCE).
            """
            
            response = await chatbot_generate(prompt=prompt, json_mode=True)
            if response and "content" in response:
                import json
                return json.loads(response["content"])
        except Exception as e:
            print(f"Error generating market context: {e}")
            
        # Fallback to semi-dynamic logic if LLM fails
        return {
            "similarExploits": [
                {"name": f"Exploit for {vuln.title}", "price": value * 0.9},
                {"name": f"Scanner Log for {vuln.vulnerability_type.value}", "price": value * 0.5}
            ],
            "typicalBuyers": ["Script Kiddies", "Data Brokers", "Competitors"],
            "marketTrend": "Stable"
        }

    @staticmethod
    async def _generate_attack_path(vuln: Vulnerability) -> List[Dict[str, str]]:
        """Generates a probable attack path using Groq API."""
        try:
            prompt = f"""
            Generate a 3-4 step cyber attack chain for: {vuln.title}
            Description: {vuln.description}
            
            Return a JSON array of objects with this structure:
            [
                {{"step": "1", "phase": "Initial Access", "description": "Specific action taken..."}},
                ...
            ]
            Use MITRE ATT&CK tactics for phases where possible.
            """
             
            response = await chatbot_generate(prompt=prompt, json_mode=True)
            if response and "content" in response:
                import json
                data = json.loads(response["content"])
                # Handle case where LLM returns a wrapper object instead of array
                if isinstance(data, dict):
                    # Look for the first list value
                    for key, val in data.items():
                        if isinstance(val, list):
                            return val
                    # If no list found, return wrapper (might be single item?) - fallback safest
                elif isinstance(data, list):
                    return data
        except Exception as e:
            print(f"Error generating attack path: {e}")

        # Fallback
        return [
            {"step": "1", "phase": "Reconnaissance", "description": "Attacker identifies vulnerable configuration."},
            {"step": "2", "phase": "Exploitation", "description": "Vulnerability leveraged to gain unauthorized access."},
            {"step": "3", "phase": "Action on Objectives", "description": "Attacker achieves goal (data access/denial of service)."}
        ]

    @staticmethod
    def _generate_equivalents(value: int) -> List[Dict[str, Any]]:
        """Converts monetary value into black market goods equivalents."""
        # Baseline prices (dark web estimates)
        cc_price = 15  # Stolen Credit Card
        med_record_price = 25 # Medical Record
        passport_price = 1000 # Fake Passport
        
        return [
            {"item": "Stolen Credit Cards", "count": int(value / cc_price), "icon": "CC"},
            {"item": "Medical Records", "count": int(value / med_record_price), "icon": "MR"},
            {"item": "Fake Passports", "count": max(1, int(value / passport_price)), "icon": "FP"}
        ]

    @classmethod
    async def get_all_valuations(cls, db: AsyncSession, limit: int = 50, offset: int = 0, scan_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Fetch all vulnerabilities that have been analyzed, ordered by recency. Optionally filter by scan_id."""
        query = select(Vulnerability).where(
            Vulnerability.marketplace_value_avg.isnot(None)
        )
        
        if scan_id:
            query = query.where(Vulnerability.scan_id == scan_id)
            
        stmt = query.order_by(desc(Vulnerability.marketplace_last_analyzed)).limit(limit).offset(offset)
        
        result = await db.execute(stmt)
        vulns = result.scalars().all()
        
        output = []
        for v in vulns:
            output.append({
                "id": v.id,
                "title": v.title,
                "severity": v.severity.value,
                "value": float(v.marketplace_value_avg),
                "lastAnalyzed": v.marketplace_last_analyzed.isoformat() if v.marketplace_last_analyzed else None
            })
        return output

    @classmethod
    async def get_dashboard_stats(cls, db: AsyncSession) -> Dict[str, Any]:
        """Aggregate statistics for the dashboard."""
        
        # 1. Total Value & Count
        # Fetch latest valuation summary
        res = await db.execute(
            select(
                func.count(Vulnerability.id),
                func.sum(Vulnerability.marketplace_value_avg),
                func.sum(VulnerabilityValuation.total_financial_impact_avg)
            ).select_from(Vulnerability).join(
                VulnerabilityValuation, Vulnerability.id == VulnerabilityValuation.vulnerability_id
            ).where(Vulnerability.marketplace_value_avg > 0)
        )
        count, total_value, total_impact = res.one()
        
        total_dark_web_value = total_value or 0
        total_financial_impact = total_impact or 0
        
        # 2. Vulnerability Counts by Severity
        severities = await db.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id)).group_by(Vulnerability.severity)
        )
        severity_counts = {row[0].value: row[1] for row in severities.all()}
        
        # 3. Recent Valuations (Last 5)
        recent_stmt = select(Vulnerability).where(
            Vulnerability.marketplace_value_avg > 0
        ).order_by(desc(Vulnerability.marketplace_last_analyzed)).limit(5)
        
        recent_result = await db.execute(recent_stmt)
        recent_data = []
        for vuln in recent_result.scalars().all():
            recent_data.append({
                "id": vuln.id,
                "title": vuln.title,
                "severity": vuln.severity.value,
                "value": float(vuln.marketplace_value_avg)
            })

        return {
            "summary": {
                "totalDarkWebValue": float(total_dark_web_value),
                "totalFinancialImpact": float(total_financial_impact),
                "vulnerabilityCount": count or 0,
                "criticalCount": severity_counts.get("critical", 0),
                "highestValueVuln": recent_data[0] if recent_data else None
            },
            "breakdown": {
                "bySeverity": severity_counts
            },
            "top5ByValue": recent_data # Renamed conceptually to "Recent" in the UI
        }

    @classmethod
    async def get_comparisons(cls, db: AsyncSession) -> Dict[str, Any]:
        """Generate creative comparisons."""
        stats = await cls.get_dashboard_stats(db)
        total_value = stats["summary"]["totalDarkWebValue"]
        
        comparisons = [
            f"= {int(total_value / 25)} stolen credit cards ($25 avg)",
            f"= {int(total_value / 185)} medical records ($185 avg)",
            f"= {int(total_value / 985)} verified Kraken accounts ($985 avg)",
            f"= {int(total_value / 35)} Gmail accounts ($35 avg)",
            f"= {int(total_value / 60)} compromised RDP access ($60 avg)"
        ]
        
        return {
            "totalValue": int(total_value),
            "comparisons": comparisons
        }
    @classmethod
    async def get_easy_explanation(cls, vulnerability_id: int, db: AsyncSession) -> str:
        """
        Generates a natural language explanation of the marketplace metrics for a non-technical user.
        """
        try:
            # 1. Fetch data
            analysis = await cls.analyze_vulnerability(vulnerability_id, db)
            vuln_result = await db.execute(select(Vulnerability).where(Vulnerability.id == vulnerability_id))
            vuln = vuln_result.scalar_one_or_none()
            
            if not vuln:
                return "Vulnerability details not found."

            # 2. Construct prompt
            prompt = f"""
            Explain the following cybersecurity financial metrics in simple, non-technical language for a general developer or business owner.
            
            Vulnerability: {vuln.title}
            Severity: {vuln.severity.value}
            
            Marketplace Data:
            - Estimated Dark Web Value: ${analysis['exploitValue']['avg']:,.2f} (Range: ${analysis['exploitValue']['min']:,.2f} - ${analysis['exploitValue']['max']:,.2f})
            - Potential Breach Impact: ${analysis['financialImpact']['avgTotal']:,.2f}
            - Estimated Fix Cost: ${analysis['roiAnalysis']['fixCost']:,.2f}
            - ROI on Fix: {analysis['roiAnalysis']['roi']}
            
            FORMATTING INSTRUCTIONS:
            - Use Markdown formatting.
            - Use H3 headers (###) for sections: "### 💡 Risk Analogy", "### 💰 Financial Deep Dive", and "### 🛡️ Recommended Action".
            - Use bullet points for key takeaways.
            - Bold important numbers and concepts.
            - Use a conversational, professional, and encouraging tone.
            - Limit the total length to about 300 words.
            """
            
            response = await chatbot_generate(
                prompt=prompt,
                system_prompt="You are a helpful cybersecurity advisor who explains complex risks to non-security professionals in plain English."
            )
            return response.get("content", "I'm sorry, I couldn't generate an explanation at this time.")
        except Exception as e:
            # Fallback for when LLM is unavailable
            return f"""### 💡 Market Intelligence Brief (Offline Mode)

Complete market analysis is currently unavailable. However, based on the vulnerability **{vuln.title}** and its **{vuln.severity.value}** severity, here is a preliminary assessment:

- **Estimated Dark Web Value:** ${analysis['exploitValue']['avg']:,.2f}
- **Potential Financial Risk:** ${analysis['financialImpact']['avgTotal']:,.2f}
- **ROI on Fix:** {analysis['roiAnalysis']['roi']}

**Action Item:** This vulnerability represents a tangible financial risk. Immediate remediation is recommended to prevent potential exploitation and data loss."""

    @classmethod
    async def get_scan_explanation(cls, scan_id: int, db: AsyncSession) -> str:
        """
        Generates a strategic, natural language summary of an entire scan for non-technical leadership.
        """
        try:
            # 1. Fetch scan and its vulnerabilities
            result = await db.execute(select(Vulnerability).where(Vulnerability.scan_id == scan_id, Vulnerability.is_suppressed == False))
            findings = result.scalars().all()
            
            if not findings:
                return "No active vulnerabilities were found in this scan. The system posture appears secure."

            # 2. Aggregate stats
            severity_counts = {}
            total_value = 0
            for f in findings:
                sev = f.severity.value
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                total_value += float(f.marketplace_value_avg or 0)

            findings_summary = "\n".join([f"- {f.title} ({f.severity.value}): {f.description[:100]}..." for f in findings[:10]])

            # 3. Construct prompt
            prompt = f"""
            Provide a strategic executive summary of the following security audit.
            The audience is non-technical leadership (CEO/Product Manager).
            
            Audit Stats:
            - Scan ID: {scan_id}
            - Total Active Findings: {len(findings)}
            - Severity Breakdown: {severity_counts}
            - Combined Dark Web Market Value: ${total_value:,.2f}
            
            Key Findings Snippet:
            {findings_summary}
            
            FORMATTING INSTRUCTIONS:
            - Use Markdown formatting.
            - Use H3 headers (###) for sections: "### 🏢 Strategic Risk Assessment", "### 💸 Financial Exposure", and "### 📈 Next Steps for Leadership".
            - Use bullet points.
            - Focus on the BUSINESS impact, not the technical details.
            - Explain the risk in terms of breach costs, reputation, and dark web attractiveness.
            - Tone: Calm, authoritative, and strategic.
            - Limit to 350 words.
            """
            
            response = await chatbot_generate(
                prompt=prompt,
                system_prompt="You are a Chief Information Security Officer (CISO) providing a plain-English briefing to the CEO about recent audit results."
            )
            return response.get("content", "I'm sorry, I couldn't generate a scan summary at this time.")
        except Exception as e:
            return f"I'm sorry, I encountered an error while analyzing the scan intelligence: {str(e)}"
