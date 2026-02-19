
import csv
import logging
import asyncio
import argparse
import sys
from decimal import Decimal
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

# Adjust path to allow imports from backend root
# Add the parent directory (backend) to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from core.database import async_session_maker
from sqlalchemy import select
from marketplace_simulation.models import ExploitPricing, FinancialImpact

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_decimal(value: str) -> Optional[Decimal]:
    """Clean and parse string to Decimal."""
    if not value or value.strip() == "":
        return None
    
    clean_val = value.strip().replace(",", "").replace("$", "")
    try:
        if "M" in clean_val:
             clean_val = clean_val.replace("M", "")
             return Decimal(clean_val) * 1000000
        return Decimal(clean_val)
    except Exception:
        return None

def parse_int(value: str) -> Optional[int]:
    """Clean and parse string to int."""
    if not value or value.strip() == "":
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None

async def import_exploit_pricing(file_path: str):
    """Import Exploit Pricing data from CSV."""
    logger.info(f"Starting import for Exploit Pricing from {file_path}")
    
    if not Path(file_path).exists():
        logger.error(f"File not found: {file_path}")
        return

    success_count = 0
    duplicate_count = 0
    error_count = 0
    
    rows_to_insert = []

    try:
        with open(file_path, mode='r', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile)
            
            async with async_session_maker() as session:
                existing_stmt = select(ExploitPricing.vulnerability_type)
                result = await session.execute(existing_stmt)
                existing_vulns = {row[0] for row in result.fetchall()}

                for row in reader:
                    try:
                        vuln_type = row.get("Vulnerability_Type", "").strip()
                        if not vuln_type:
                            continue

                        # Check if exists in DB (double check)
                        stmt = select(ExploitPricing).where(ExploitPricing.vulnerability_type == vuln_type)
                        result = await session.execute(stmt)
                        existing_pricing = result.scalar_one_or_none()

                        if existing_pricing:
                            duplicate_count += 1
                            continue
                            
                        # Map fields
                        pricing = ExploitPricing(
                            vulnerability_type=vuln_type,
                            severity=row.get("Severity", "").strip() if row.get("Severity") else None,
                            target_industry=row.get("Target_Industry", "").strip(),
                            min_usd=parse_decimal(row.get("Min_USD")),
                            max_usd=parse_decimal(row.get("Max_USD")),
                            avg_usd=parse_decimal(row.get("Avg_USD")),
                            complexity=row.get("Complexity", "").strip(),
                            buyer_type=row.get("Buyer_Type", "").strip(),
                            trend=row.get("Trend", "").strip(),
                            reference=row.get("Reference", "").strip(),
                            updated=parse_int(row.get("Updated"))
                        )
                        session.add(pricing)
                        await session.commit()
                        success_count += 1
                        existing_vulns.add(vuln_type) # simple in-memory dup check for batch

                    except Exception as e:
                        logger.error(f"Error processing row {row}: {e}")
                        await session.rollback()
                        error_count += 1
    except Exception as e:
        logger.error(f"Failed to process CSV file: {e}")
        return

    logger.info("Exploit Pricing Import Summary:")
    logger.info(f"  Processed: {success_count + duplicate_count + error_count}")
    logger.info(f"  Imported: {success_count}")
    logger.info(f"  Duplicates: {duplicate_count}")
    logger.info(f"  Errors: {error_count}")


async def import_financial_impact(file_path: str):
    """Import Financial Impact data from CSV."""
    logger.info(f"Starting import for Financial Impact from {file_path}")
    
    if not Path(file_path).exists():
        logger.error(f"File not found: {file_path}")
        return

    success_count = 0
    error_count = 0
    rows_to_insert = []

    try:
        with open(file_path, mode='r', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile)
            
            async with async_session_maker() as session:
                 for row in reader:
                    try:
                        cost_cat = row.get("Cost_Category", "").strip()
                        if not cost_cat: 
                            continue

                        # Check if exists (composite key approximation)
                        stmt = select(FinancialImpact).where(
                            (FinancialImpact.cost_category == cost_cat) & 
                            (FinancialImpact.industry == row.get("Industry", "").strip()) &
                            (FinancialImpact.company_size == row.get("Company_Size", "").strip())
                        )
                        result = await session.execute(stmt)
                        existing_impact = result.scalar_one_or_none()
                        
                        if existing_impact:
                             continue

                        # Special handling for values like "144/rec" - minimal parsing for now as requested
                        # complex parsing logic could be added here if schemas strictly require pure numbers,
                        # but schema allows NULLs for numeric fields, so we try parse, else ignore.
                        
                        impact = FinancialImpact(
                            cost_category=cost_cat,
                            industry=row.get("Industry", "").strip(),
                            company_size=row.get("Company_Size", "").strip(),
                            min_cost=parse_decimal(row.get("Min_Cost")),
                            max_cost=parse_decimal(row.get("Max_Cost")),
                            avg_cost=parse_decimal(row.get("Avg_Cost")),
                            calculation_method=row.get("Calculation_Method", "").strip(),
                            real_world_example=row.get("Real_World_Example", "").strip(),
                            source=row.get("Source", "").strip(),
                            year=parse_int(row.get("Year"))
                        )
                        session.add(impact)
                        await session.commit()
                        success_count += 1
                    except Exception as e:
                        logger.error(f"Error processing row {row}: {e}")
                        await session.rollback()
                        error_count += 1

    except Exception as e:
        logger.error(f"Failed to process CSV file: {e}")
        return

    logger.info("Financial Impact Import Summary:")
    logger.info(f"  Processed: {success_count + error_count}")
    logger.info(f"  Imported: {success_count}")
    logger.info(f"  Errors: {error_count}")

async def main():
    parser = argparse.ArgumentParser(description="Import Marketplace Simulation Data")
    parser.add_argument("--exploits", action="store_true", help="Import Exploit Pricing Data")
    parser.add_argument("--finance", action="store_true", help="Import Financial Impact Data")
    parser.add_argument("--all", action="store_true", help="Import All Data")
    
    args = parser.parse_args()
    
    base_path = Path(__file__).parent.parent / "data"
    
    if args.exploits or args.all:
        await import_exploit_pricing(str(base_path / "dark.csv"))
        
    if args.finance or args.all:
        await import_financial_impact(str(base_path / "finance.csv"))

    if not (args.exploits or args.finance or args.all):
        parser.print_help()

if __name__ == "__main__":
    asyncio.run(main())
