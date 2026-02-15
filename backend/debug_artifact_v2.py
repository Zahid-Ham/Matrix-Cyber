import asyncio
import json
import logging
from sqlalchemy import select
from core.database import async_session_maker
from models.forensic import ForensicArtifact

# Suppress all logging
logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)

async def list_artifacts(scan_id):
    async with async_session_maker() as db:
        res = await db.execute(
            select(ForensicArtifact).join(ForensicArtifact.forensic_record).where(ForensicArtifact.forensic_record.has(scan_id=scan_id))
        )
        artifacts = res.scalars().all()
        
        output = []
        for art in artifacts:
            output.append({
                "id": art.artifact_evidence_id,
                "name": art.name,
                "type": art.artifact_type,
                "metadata": art.metadata_json
            })
        
        print(json.dumps(output, indent=2))

if __name__ == "__main__":
    import sys
    scan_id = int(sys.argv[1]) if len(sys.argv) > 1 else 84
    asyncio.run(list_artifacts(scan_id))
