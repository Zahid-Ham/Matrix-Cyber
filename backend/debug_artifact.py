import asyncio
import json
from sqlalchemy import select
from core.database import async_session_maker
from models.forensic import ForensicArtifact

async def list_artifacts(scan_id):
    async with async_session_maker() as db:
        # Get forensic record ID
        res = await db.execute(
            select(ForensicArtifact).join(ForensicArtifact.forensic_record).where(ForensicArtifact.forensic_record.has(scan_id=scan_id))
        )
        artifacts = res.scalars().all()
        
        if not artifacts:
            print(f"No artifacts found for scan {scan_id}.")
            return
            
        print(f"--- Artifacts for Scan {scan_id} ---")
        for art in artifacts:
            print(f"ID: {art.artifact_evidence_id} | Name: {art.name} | Type: {art.artifact_type}")
            print(f"Metadata: {json.dumps(art.metadata_json, indent=2)}")
            print("-" * 40)

if __name__ == "__main__":
    import sys
    scan_id = int(sys.argv[1]) if len(sys.argv) > 1 else 84
    asyncio.run(list_artifacts(scan_id))
