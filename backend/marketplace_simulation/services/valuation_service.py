
import random
from decimal import Decimal
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy import select, or_, and_, func, desc, cast, Text
from sqlalchemy.ext.asyncio import AsyncSession
from marketplace_simulation.models import ExploitPricing, FinancialImpact, VulnerabilityValuation
from models import Vulnerability, Severity

class ValuationService:
    """
    Advanced service for calculating exploit values based on market trends,
    severity, industry, and complexity.
    """

    # Multipliers Configuration
    SEVERITY_MULTIPLIERS = {
        "critical": 3.5,
        "high": 2.0,
        "medium": 1.2,
        "low": 0.6,
        "info": 0.1
    }

    INDUSTRY_MULTIPLIERS = {
        "Government": 4.0,
        "Financial": 3.5,
        "Healthcare": 3.0,
        "Manufacturing": 2.5,
        "Technology": 2.0,
        "Retail": 1.8,
        "General": 1.0
    }

    SCALE_MULTIPLIERS = {
        "Enterprise": 3.0,
        "MidMarket": 2.0,
        "Small": 1.0
    }

    # Complexity: Inverse relationship (Easier to exploit = Higher value/demand usually, 
    # OR Harder = Pricier? 
    # User prompt: "Complexity Multipliers (inverse - easier = more valuable): Very High: 0.5x, Low: 2.0x"
    COMPLEXITY_MULTIPLIERS = {
        "Very High": 0.5,
        "High": 0.7,
        "Medium": 1.2,
        "Low": 2.0
    }

    @classmethod
    async def calculate_exploit_value(
        cls, 
        db: AsyncSession, 
        vulnerability: Vulnerability,
        industry: str = "General",
        company_size: str = "Small"
    ) -> Dict[str, Any]:
        """
        Main entry point for calculating exploit value.
        Strategy: Exact -> Similar -> Category -> Heuristic -> CVSS
        """
        
        # 1. Try Exact Match
        exact_match = await cls._find_exact_match(db, vulnerability)
        base_data = None
        confidence = 0
        source = ""
        
        if exact_match:
            base_data = exact_match
            confidence = 95
            source = f"Exact Match: {exact_match.vulnerability_type}"
        else:
            # 2. Try Similar Match
            similar_match = await cls._find_similar_match(db, vulnerability)
            if similar_match:
                base_data = similar_match
                confidence = 85
                source = f"Similar Type Match: {similar_match.vulnerability_type}"
            else:
                # 3. Try Category Match (Scanning description or using OWASP category)
                category_match = await cls._find_category_match(db, vulnerability)
                if category_match:
                    base_data = category_match
                    confidence = 70
                    source = f"Category Match: {category_match.vulnerability_type}"
                else:
                    # 4. Try Heuristic Match (Keyword based)
                    heuristic_match = cls._heuristics_match(vulnerability)
                    if heuristic_match:
                        base_data = heuristic_match
                        confidence = 65
                        source = f"Heuristic Model: {heuristic_match['type']}"
                    else:
                        # 5. CVSS Fallback
                        base_data = cls._estimate_from_cvss(vulnerability)
                        confidence = 50
                        source = "CVSS-based Estimation"

        # Extract base values
        # Extract base values
        if isinstance(base_data, ExploitPricing):
            base_price_avg = float(base_data.avg_usd)
            base_price_min = float(base_data.min_usd)
            base_price_max = float(base_data.max_usd)
        elif base_data:
            base_price_avg = base_data["avg"]
            base_price_min = base_data["min"]
            base_price_max = base_data["max"]
        else:
            base_price_avg = 0.0
            base_price_min = 0.0
            base_price_max = 0.0

        # FALLBACK: Ensure minimum value based on severity if no specific data found
        if base_price_avg <= 0:
            severity_min_map = {
                "critical": 3500.0,
                "high": 1500.0,
                "medium": 500.0,
                "low": 100.0,
                "info": 0.0
            }
            fallback_price = severity_min_map.get(vulnerability.severity.value, 0.0)
            if fallback_price > 0:
                base_price_avg = fallback_price
                base_price_min = fallback_price * 0.8
                base_price_max = fallback_price * 1.2
                source = f"Severity Baseline ({vulnerability.severity.value.title()})"
                confidence = 40

        # 5. Calculate Multipliers
        sev_mult = cls.SEVERITY_MULTIPLIERS.get(vulnerability.severity.value, 1.0)
        ind_mult = cls.INDUSTRY_MULTIPLIERS.get(industry, 1.0)
        scale_mult = cls.SCALE_MULTIPLIERS.get(company_size, 1.0)
        
        # Complexity mapping
        complexity_key = "Medium"
        if vulnerability.cvss_attack_complexity:
             if vulnerability.cvss_attack_complexity.value == "L": complexity_key = "Low"
             elif vulnerability.cvss_attack_complexity.value == "H": complexity_key = "High"
        
        comp_mult = cls.COMPLEXITY_MULTIPLIERS.get(complexity_key, 1.2)

        # CVSS Bonus
        cvss = vulnerability.cvss_score or 0.0
        cvss_bonus_pct = 0.0
        if cvss >= 9.0: cvss_bonus_pct = 0.60
        elif cvss >= 7.0: cvss_bonus_pct = 0.30
        elif cvss >= 5.0: cvss_bonus_pct = 0.10
        
        cvss_mult = 1.0 + cvss_bonus_pct

        # 6. Final Calculation
        # Formula: Base * Sev * Ind * Scale * Comp * CVSS
        total_mult = sev_mult * ind_mult * scale_mult * comp_mult * cvss_mult
        
        calculated_val = base_price_avg * total_mult
        
        final_min = calculated_val * 0.75
        final_max = calculated_val * 1.25
        
        # Random realism
        random_factor = 0.95 + (random.random() * 0.1) # 0.95 to 1.05
        final_avg_real = calculated_val * random_factor

        # 8. Construct Return Object
        return {
            "exploitValue": {
                "min": int(final_min),
                "max": int(final_max),
                "avg": int(final_avg_real),
                "currency": "USD",
                "strategy": source,
                "confidence": confidence
            },
            "dataSource": source,
            "breakdown": {
                "basePrice": base_price_avg,
                "severityMultiplier": sev_mult,
                "industryMultiplier": ind_mult,
                "scaleMultiplier": scale_mult,
                "complexityMultiplier": comp_mult,
                "cvssBonus": cvss_bonus_pct
            },
            "comparableExamples": await cls._get_comparable_examples(db, vulnerability)
        }

    @staticmethod
    def _heuristics_match(vuln: Vulnerability) -> Optional[Dict[str, Any]]:
        """
        Estimate base price based on vulnerability type keywords when no DB match exists.
        """
        vuln_type = str(vuln.vulnerability_type.value).lower()
        title = vuln.title.lower()
        
        # Base prices for common categories (approximate market rates)
        heuristics = [
            {"keywords": ["rce", "remote code execution", "command injection"], "base": 50000, "type": "RCE"},
            {"keywords": ["sql", "injection", "sqli"], "base": 15000, "type": "SQL Injection"},
            {"keywords": ["xss", "cross-site scripting"], "base": 2500, "type": "XSS"},
            {"keywords": ["auth", "login", "password", "credential"], "base": 8000, "type": "Authentication Bypass"},
            {"keywords": ["idor", "access control"], "base": 5000, "type": "Broken Access Control"},
            {"keywords": ["deserialization"], "base": 20000, "type": "Insecure Deserialization"},
            {"keywords": ["xxe"], "base": 7000, "type": "XXE"},
            {"keywords": ["ssrf"], "base": 10000, "type": "SSRF"},
        ]
        
        for h in heuristics:
            if any(k in vuln_type or k in title for k in h["keywords"]):
                return {
                    "min": h["base"] * 0.8,
                    "max": h["base"] * 1.2,
                    "avg": h["base"],
                    "type": h["type"]
                }
        return None

    @classmethod
    def estimate_fix_cost(cls, vuln: Vulnerability) -> dict:
        """
        Estimate fix cost based on severity, type, and complexity.
        Returns: { "cost": float, "hours": int, "rationale": str }
        """
        # Base hours by severity
        base_hours_map = {
            "critical": 40,
            "high": 20,
            "medium": 8,
            "low": 4,
            "info": 1
        }
        hours = base_hours_map.get(vuln.severity.value, 4)
        
        # Type multipliers
        vuln_type = str(vuln.vulnerability_type.value).lower()
        type_mult = 1.0
        
        if "architecture" in vuln_type or "design" in vuln_type:
            type_mult = 3.0 # Design flaws are hard to fix
        elif "injection" in vuln_type:
            type_mult = 1.5 # Requires code changes + testing
        elif "config" in vuln_type or "header" in vuln_type:
            type_mult = 0.5 # quick config fix
            
        # Complexity multiplier (from model if available, else random jitter)
        complexity_mult = 1.0
        if vuln.cvss_attack_complexity and vuln.cvss_attack_complexity.value == "H":
             complexity_mult = 1.5 # Harder to exploit often means obscure code -> harder to fix? 
             # Or maybe clearer: High complexity means the code is complex.
        
        # Jitter
        jitter = random.uniform(0.9, 1.1)
        
        total_hours = int(hours * type_mult * complexity_mult * jitter)
        rate = 150 # $150/hr avg developer cost
        total_cost = total_hours * rate
        
        return {
            "cost": total_cost,
            "hours": total_hours,
            "rate": rate
        }

    @staticmethod
    async def _find_exact_match(db: AsyncSession, vuln: Vulnerability) -> Optional[ExploitPricing]:
        """Find match by explicit type name and severity."""
        stmt = select(ExploitPricing).where(
            func.lower(ExploitPricing.vulnerability_type) == func.lower(str(vuln.vulnerability_type.value)),
            func.lower(cast(ExploitPricing.severity, Text)) == func.lower(vuln.severity.value)
        ).order_by(desc(ExploitPricing.updated)).limit(1)
        
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def _find_similar_match(db: AsyncSession, vuln: Vulnerability) -> Optional[ExploitPricing]:
        """Find match by partial name or flexible severity."""
        # Try matching type loosely
        clean_type = str(vuln.vulnerability_type.value).replace("_", " ")
        stmt = select(ExploitPricing).where(
            ExploitPricing.vulnerability_type.ilike(f"%{clean_type}%")
        ).order_by(desc(ExploitPricing.updated)).limit(1)
        
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def _find_category_match(db: AsyncSession, vuln: Vulnerability) -> Optional[ExploitPricing]:
        """Find match by OWASP category."""
        if not vuln.owasp_category:
            return None
            
        # Extract main category keyword (e.g., "Injection" from "A03:2021-Injection")
        category_keyword = vuln.owasp_category.split("-")[-1]
        
        stmt = select(ExploitPricing).where(
            ExploitPricing.vulnerability_type.ilike(f"%{category_keyword}%")
        ).order_by(desc(ExploitPricing.updated)).limit(1)
        
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    def _estimate_from_cvss(vuln: Vulnerability) -> Dict[str, float]:
        """Fallback estimation based purely on CVSS."""
        score = vuln.cvss_score or 5.0
        
        # Base value derivation (Exponential curve based on score)
        # Score 10 -> $100k base
        # Score 5 -> $5k base
        # Score 0 -> $0
        
        base_value = 1000 * (1.8 ** score)  # rough curve
        # Cap/Floor adjustment
        base_value = max(500, min(base_value, 250000))
        
        return {
            "min": base_value * 0.8,
            "max": base_value * 1.2,
            "avg": base_value
        }

    @staticmethod
    async def _get_comparable_examples(db: AsyncSession, vuln: Vulnerability) -> List[Dict[str, Any]]:
        """Get list of comparable exploits for context."""
        # Find 3 items with same severity
        stmt = select(ExploitPricing).where(
            func.lower(cast(ExploitPricing.severity, Text)) == func.lower(vuln.severity.value)
        ).order_by(func.random()).limit(2)
        
        result = await db.execute(stmt)
        rows = result.scalars().all()
        
        return [
            {
                "type": row.vulnerability_type,
                "price": float(row.avg_usd or 0)
            }
            for row in rows
        ]
