
from decimal import Decimal
from typing import Optional, Dict, Any, List
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from marketplace_simulation.models import FinancialImpact
from models import Vulnerability, Severity

class FinancialImpactService:
    """
    Service to estimate financial impact of security breaches based on
    industry benchmarks, downtime, data records, and regulatory fines.
    """

    @classmethod
    async def calculate_breach_impact(
        cls, 
        db: AsyncSession, 
        vulnerability: Vulnerability, 
        profile: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Calculate estimated breach impact.
        """
        import random
        
        # Default profile with some random variation for realism if not provided
        base_revenue = profile.get("revenue", 1000000)
        base_users = profile.get("user_count", 10000)
        
        # Add jitter if using defaults (to prevent identical numbers across vulns)
        if "revenue" not in profile:
            base_revenue = base_revenue * random.uniform(0.8, 1.2)
        if "user_count" not in profile:
            base_users = int(base_users * random.uniform(0.8, 1.2))

        industry = profile.get("industry", "General")
        size = profile.get("size", "Small")
        revenue = float(base_revenue)
        user_count = int(base_users)
        has_gdpr = profile.get("has_gdpr_exposure", False)
        
        impact = {}

        # 1. Get Industry Benchmark
        benchmark = await cls._get_benchmark(db, industry, size)
        if benchmark:
            impact["baseBreachCost"] = {
                "min": float(benchmark.min_cost or 0),
                "max": float(benchmark.max_cost or 0),
                "avg": float(benchmark.avg_cost or 0),
                "source": benchmark.real_world_example
            }
        else:
             # Fallback
             impact["baseBreachCost"] = {
                "min": 10000.0,
                "max": 50000.0,
                "avg": 25000.0,
                "source": "Estimated fallback"
            }

        # 2. Calculate Downtime Costs
        downtime_rate = await cls._get_downtime_rate(db, industry, size)
        # Use vuln type to better estimate downtime
        estimated_downtime = cls._estimate_downtime(vulnerability)
        
        rate_per_hour = float(downtime_rate.avg_cost or 5000.0) if downtime_rate else 5000.0
        
        impact["downtimeCost"] = {
            "hours": estimated_downtime,
            "ratePerHour": rate_per_hour,
            "totalCost": float(estimated_downtime * rate_per_hour),
            "calculation": downtime_rate.calculation_method if (downtime_rate and downtime_rate.calculation_method) else "Industry Estimate"
        }

        # 3. Data Breach Costs (Per Record)
        record_type = cls._determine_record_type(vulnerability, profile)
        per_record_cost_data = await cls._get_per_record_cost(db, record_type)
        per_record_cost = float(per_record_cost_data.avg_cost) if per_record_cost_data else 150.0 # Default $150
        
        # Scale affected users based on vulnerability scope (if we have that info)
        affected_users_est = user_count
        if vulnerability.scope_impact and "affected_endpoints" in vulnerability.scope_impact:
            # Heuristic: limit exposure based on scope?
            # For now, let's just use a percentage based on severity if scope is small
            pass

        impact["dataBreachCost"] = {
            "affectedRecords": affected_users_est,
            "costPerRecord": per_record_cost,
            "totalCost": affected_users_est * per_record_cost,
            "recordType": record_type
        }

        # 4. Regulatory Fines
        impact["regulatoryFines"] = []
        
        # GDPR
        vuln_exposes_pii = cls._check_pii_exposure(vulnerability)
        
        if has_gdpr and vuln_exposes_pii:
            # GDPR max is greater of 20M EUR or 4% global turnover
            # Assuming revenue is in USD, 20M EUR approx 22M USD
            max_gdpr = max(22000000.0, revenue * 0.04)
            min_gdpr = 0.0
            
            # Simple severity scaling for estimation
            likelihood = "High" if vulnerability.severity.value in ["critical", "high"] else "Medium"
            estimated_fine = max_gdpr * 0.02 if likelihood == "High" else max_gdpr * 0.001 # Reduced for realism
            
            impact["regulatoryFines"].append({
                "regulation": "GDPR",
                "minFine": min_gdpr,
                "maxFine": max_gdpr,
                "estimatedFine": estimated_fine,
                "likelihood": likelihood
            })

        # HIPAA
        if industry == "Healthcare" and (vuln_exposes_pii or cls._check_phi_exposure(vulnerability)):
            # HIPAA tiers range from $100 to $50,000 per violation
            # Max $1.5M per year per category
            max_hipaa = min(1500000.0, 50000.0 * user_count)
            estimated_hipaa = max_hipaa * 0.5 
            
            impact["regulatoryFines"].append({
                "regulation": "HIPAA",
                "minFine": 100.0,
                "maxFine": max_hipaa,
                "estimatedFine": estimated_hipaa,
                "perViolation": True,
                "likelihood": "High"
            })

        # 5. Additional Costs
        forensics_cost = cls._get_forensics_cost(size)
        notification_cost = cls._get_notification_cost(user_count)
        credit_monitoring = user_count * 20.0 if vuln_exposes_pii else 0
        legal_settlement = cls._estimate_legal_costs(industry, user_count)
        reputation_repair = cls._get_reputation_cost(size)
        
        impact["additionalCosts"] = {
            "forensics": forensics_cost,
            "notification": notification_cost,
            "creditMonitoring": credit_monitoring,
            "legalSettlement": legal_settlement,
            "reputationRepair": reputation_repair,
            "total": forensics_cost + notification_cost + credit_monitoring + legal_settlement + reputation_repair
        }

        # 6. Indirect Business Impact
        churn_rate = cls._get_churn_rate(vulnerability.severity)
        customer_ltv = float(profile.get("customer_ltv", 1000.0))
        lost_customers = user_count * churn_rate
        total_churn_loss = lost_customers * customer_ltv
        
        current_premium = float(profile.get("cyber_insurance_premium", 50000.0))
        premium_increase = current_premium * 0.25
        
        impact["indirectImpact"] = {
            "customerChurn": {
                "rate": churn_rate,
                "lostCustomers": int(lost_customers),
                "lifetimeValue": customer_ltv,
                "totalLoss": total_churn_loss
            },
            "insurancePremiumIncrease": {
                "currentPremium": current_premium,
                "increasePercentage": 25,
                "additionalCost": premium_increase
            },
            "total": total_churn_loss + premium_increase
        }

        # 7. Total Calculation
        total_fines = sum(f.get("estimatedFine", 0) for f in impact["regulatoryFines"])
        
        # Summing averages/estimates for the total calculation
        avg_total = (
            impact["baseBreachCost"]["avg"] +
            impact["downtimeCost"]["totalCost"] +
            impact["dataBreachCost"]["totalCost"] +
            total_fines +
            impact["additionalCosts"]["total"] +
            impact["indirectImpact"]["total"]
        )

        min_total = avg_total * 0.7 # variance
        max_total = avg_total * 1.4

        impact["totalImpact"] = {
            "minTotal": min_total,
            "maxTotal": max_total,
            "avgTotal": avg_total,
            "breakdown": {
                "baseBreach": (impact["baseBreachCost"]["avg"] / avg_total) * 100 if avg_total else 0,
                "downtime": (impact["downtimeCost"]["totalCost"] / avg_total) * 100 if avg_total else 0,
                "dataBreach": (impact["dataBreachCost"]["totalCost"] / avg_total) * 100 if avg_total else 0,
                "fines": (total_fines / avg_total) * 100 if avg_total else 0,
                "additional": (impact["additionalCosts"]["total"] / avg_total) * 100 if avg_total else 0,
                "indirect": (impact["indirectImpact"]["total"] / avg_total) * 100 if avg_total else 0
            }
        }

        return impact

    # =========================================================================
    # Helpers
    # =========================================================================

    @staticmethod
    async def _get_benchmark(db: AsyncSession, industry: str, size: str) -> Optional[FinancialImpact]:
        """Get industry benchmark from DB."""
        stmt = select(FinancialImpact).where(
            FinancialImpact.industry.ilike(f"%{industry}%"),
            FinancialImpact.company_size.ilike(f"%{size}%"),
            FinancialImpact.cost_category.ilike("%Benchmark%")
        ).limit(1)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def _get_downtime_rate(db: AsyncSession, industry: str, size: str) -> Optional[FinancialImpact]:
        """Get downtime rate."""
        stmt = select(FinancialImpact).where(
            FinancialImpact.industry.ilike(f"%{industry}%"),
            FinancialImpact.cost_category.ilike("%Downtime%")
        ).limit(1)
        result = await db.execute(stmt)
        row = result.scalar_one_or_none()
        
        # Scale by size if row is generic
        # (This logic implies DB has specific rows, but we might need manual scaling if not found)
        return row

    @staticmethod
    def _estimate_downtime(vulnerability: Vulnerability) -> int:
        """Estimate hours of downtime based on type and severity."""
        sev_val = vulnerability.severity.value
        vuln_type = str(vulnerability.vulnerability_type.value).lower()
        
        base_hours = 0
        
        # Severity Baseline
        if sev_val == "critical": base_hours = 24
        elif sev_val == "high": base_hours = 8
        elif sev_val == "medium": base_hours = 2
        
        # Type Modifiers
        if "dos" in vuln_type or "denial" in vuln_type:
            base_hours *= 3 # DoS is all about downtime
        elif "rce" in vuln_type or "remote code" in vuln_type:
            base_hours *= 2 # Deep system compromise
        elif "ransomware" in vuln_type:
            base_hours *= 10 # Catastrophic
        elif "xss" in vuln_type or "csrf" in vuln_type:
             base_hours = max(1, base_hours * 0.1) # UI issues rarely cause downtime
             
        return int(base_hours)

    @staticmethod
    def _determine_record_type(vuln: Vulnerability, profile: Dict) -> str:
        """Determine type of records exposed."""
        # Check vuln type or category
        if "PII" in str(vuln.vulnerability_type) or "sensitive" in str(vuln.vulnerability_type):
            return "PII"
        if profile.get("industry") == "Healthcare":
            return "PHI"
        return "Generic" # Fallback

    @staticmethod
    async def _get_per_record_cost(db: AsyncSession, record_type: str) -> Optional[FinancialImpact]:
        """Get cost per record."""
        stmt = select(FinancialImpact).where(
            FinancialImpact.cost_category.ilike(f"%{record_type}%")
        ).limit(1)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    def _check_pii_exposure(vuln: Vulnerability) -> bool:
        """Check if vulnerability exposes PII."""
        keywords = ["pii", "sensitive", "user", "password", "credential", "injection", "xss"]
        return any(k in str(vuln.vulnerability_type).lower() for k in keywords)

    @staticmethod
    def _check_phi_exposure(vuln: Vulnerability) -> bool:
        """Check if vulnerability exposes PHI (Protected Health Information)."""
        # Similar to PII but stricter for healthcare context
        return FinancialImpactService._check_pii_exposure(vuln)

    @staticmethod
    def _get_forensics_cost(size: str) -> float:
        if size == "Enterprise": return 100000.0
        elif size == "MidMarket": return 50000.0
        return 15000.0

    @staticmethod
    def _get_notification_cost(records: int) -> float:
        return records * 2.0 # $2 per person for mail/email/support

    @staticmethod
    def _estimate_legal_costs(industry: str, records: int) -> float:
        base = 10000.0
        if industry in ["Financial", "Healthcare"]:
            base = 50000.0
        
        return base + (records * 5.0)

    @staticmethod
    def _get_reputation_cost(size: str) -> float:
        if size == "Enterprise": return 500000.0
        elif size == "MidMarket": return 100000.0
        return 25000.0

    @staticmethod
    def _get_churn_rate(severity: Severity) -> float:
        if severity == Severity.CRITICAL: return 0.15 # 15%
        elif severity == Severity.HIGH: return 0.10
        elif severity == Severity.MEDIUM: return 0.05
        return 0.03
