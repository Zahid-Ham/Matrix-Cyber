
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional, Dict, Any
from core.database import get_db
from marketplace_simulation.services.marketplace_service import MarketplaceService
from marketplace_simulation.services.valuation_service import ValuationService
from marketplace_simulation.services.financial_impact_service import FinancialImpactService
from marketplace_simulation.models import ExploitPricing, FinancialImpact, VulnerabilityValuation
from models import Vulnerability
from sqlalchemy import select
from pydantic import BaseModel
import subprocess
import sys
import os

router = APIRouter(
    prefix="/marketplace",
    tags=["Marketplace Simulation"]
)

# Request Models
class AnalyzeRequest(BaseModel):
    companyProfile: Optional[Dict[str, Any]] = None

class ImportRequestId(BaseModel):
    dataType: str # 'exploits' | 'finance' | 'all'

# --- Endpoints ---

@router.get("/dashboard", response_model=Dict[str, Any])
async def get_dashboard(
    project_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get overview of marketplace statistics."""
    try:
        stats = await MarketplaceService.get_dashboard_stats(db)
        return stats
    except Exception as e:
        print(f"Dashboard error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/all", response_model=List[Dict[str, Any]])
async def get_all_valuations(
    limit: int = 50,
    offset: int = 0,
    scan_id: Optional[int] = Query(None, description="Filter by Scan ID"),
    db: AsyncSession = Depends(get_db)
):
    """Get all vulnerabilities that have been analyzed, ordered by recency."""
    try:
        return await MarketplaceService.get_all_valuations(db, limit, offset, scan_id)
    except Exception as e:
        print(f"All valuations error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/comparisons", response_model=Dict[str, Any])
async def get_comparisons(
    db: AsyncSession = Depends(get_db)
):
    """Get creative comparisons for total exploit value."""
    try:
        comparisons = await MarketplaceService.get_comparisons(db)
        return comparisons
    except Exception as e:
        print(f"Comparison error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/vulnerability/{vulnerability_id}/details", response_model=Dict[str, Any])
async def get_vulnerability_details(
    vulnerability_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get detailed marketplace analysis for a single vulnerability."""
    try:
        # We reuse analyze logic to get the full view (calculated on the fly for simulation)
        # In a real app we might fetch stored JSON, but this ensures fresh simulation data
        analysis = await MarketplaceService.analyze_vulnerability(vulnerability_id, db)
        return analysis
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        print(f"Details error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/vulnerability/{vulnerability_id}/explain", response_model=Dict[str, Any])
async def get_easy_explanation(
    vulnerability_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get natural language explanation for non-technical users."""
    try:
        explanation = await MarketplaceService.get_easy_explanation(vulnerability_id, db)
        return {"explanation": explanation}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan/{scan_id}/explain", response_model=Dict[str, Any])
async def get_scan_explanation(
    scan_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get strategic executive summary for an entire scan."""
    try:
        explanation = await MarketplaceService.get_scan_explanation(scan_id, db)
        return {"explanation": explanation}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze/{vulnerability_id}", response_model=Dict[str, Any])
async def analyze_vulnerability(
    vulnerability_id: int,
    request: AnalyzeRequest,
    db: AsyncSession = Depends(get_db)
):
    """Analyze a specific vulnerability (Valuation + Impact + ROI)."""
    try:
        analysis = await MarketplaceService.analyze_vulnerability(
            vulnerability_id, 
            db, 
            request.companyProfile
        )
        return analysis
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        print(f"Analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/import", response_model=Dict[str, Any])
async def trigger_import(
    request: ImportRequestId,
    # current_user: User = Depends(get_current_admin_user) # TODO: Add Auth when available
):
    """Trigger data import via CLI utility."""
    if request.dataType not in ['exploits', 'finance', 'all']:
        raise HTTPException(status_code=400, detail="Invalid dataType")
    
    import subprocess
    import sys
    import os
    
    # Locate the importer script
    script_path = os.path.join("marketplace_simulation", "utils", "data_importer.py")
    if not os.path.exists(script_path):
         script_path = os.path.join("backend", "marketplace_simulation", "utils", "data_importer.py")
    
    cmd = [sys.executable, script_path]
    if request.dataType == 'exploits':
        cmd.append("--exploits")
    elif request.dataType == 'finance':
        cmd.append("--finance")
    elif request.dataType == 'all':
        cmd.append("--all")
        
    try:
        # Run async/detached or wait? For API, better to wait if fast, or background task.
        # Given it's a simulation, waiting is fine for small CSVs.
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.getcwd())
        
        if result.returncode != 0:
            raise Exception(f"Import failed: {result.stderr}")
            
        return {"status": "success", "message": "Import completed", "output": result.stdout}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- Existing Endpoints (Kept for compatibility/granular access) ---

@router.get("/exploits", response_model=None)
async def list_exploits(
    vulnerability_type: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """List exploit pricing data."""
    exploits = await MarketplaceService.get_exploit_pricing(db, vulnerability_type, limit)
    return exploits

@router.get("/impacts", response_model=None)
async def list_impacts(
    industry: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """List financial impact data."""
    impacts = await MarketplaceService.get_financial_impact(db, industry, limit)
    return impacts

@router.get("/valuation/{vulnerability_id}", response_model=None)
async def get_valuation(
    vulnerability_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get latest valuation for a vulnerability."""
    valuation = await MarketplaceService.get_valuation(db, vulnerability_id)
    if not valuation:
        raise HTTPException(status_code=404, detail="Valuation not found")
    return valuation

# Deprecated/Atomic endpoints can remain or be redirected
@router.post("/valuation/{vulnerability_id}", response_model=None)
async def calculate_valuation(
    vulnerability_id: int,
    industry: str = Query("General", description="Target Industry"),
    company_size: str = Query("Small", description="Company Size"),
    db: AsyncSession = Depends(get_db)
):
    """Calculate and store valuation for a vulnerability."""
    try:
         # Reuse the service method or keep atomic
        result = await db.execute(select(Vulnerability).where(Vulnerability.id == vulnerability_id))
        vuln = result.scalar_one_or_none()
        if not vuln: raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        return await ValuationService.calculate_exploit_value(db, vuln, industry, company_size)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/impact/{vulnerability_id}", response_model=None)
async def calculate_impact(
    vulnerability_id: int,
    profile: dict, 
    db: AsyncSession = Depends(get_db)
):
    """Calculate estimated financial impact of a breach."""
    try:
        result = await db.execute(select(Vulnerability).where(Vulnerability.id == vulnerability_id))
        vuln = result.scalar_one_or_none()
        if not vuln: raise HTTPException(status_code=404, detail="Vulnerability not found")

        return await FinancialImpactService.calculate_breach_impact(db, vuln, profile)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
