import asyncio
import json
from sqlalchemy import select
from core.database import get_db_context
from models.scan import Scan
from schemas.scan import ScanResponse

async def simulate_api_response(scan_id: int):
    async with get_db_context() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            print(f"Scan {scan_id} not found")
            return
        
        # Simulate Pydantic validation
        response_model = ScanResponse.model_validate(scan)
        print("--- Pydantic Serialization ---")
        print(json.dumps(response_model.model_dump(), indent=2, default=str))

if __name__ == "__main__":
    asyncio.run(simulate_api_response(44))
