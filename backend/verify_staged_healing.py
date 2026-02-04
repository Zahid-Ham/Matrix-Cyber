import asyncio
import httpx
import json

async def test_staged_healing():
    scan_id = 84
    artifact_id = "fbe32f05-8857-4146-a4f7-e21825316db0" # Finding: SQL Injection
    base_url = "http://localhost:8000"
    
    # 1. Start by reporting the issue
    print(f"--- Reporting Issue for Artifact {artifact_id} ---")
    async with httpx.AsyncClient() as client:
        # We need to skip CSRF for this test script or provide a token.
        # Since I'm running this on the server locally, I'll just hit the endpoint.
        # Note: In production/real tests, ensure CSRF middleware allows local test access or provide token.
        
        resp = await client.post(f"{base_url}/api/forensics/{scan_id}/artifacts/{artifact_id}/report-issue/")
        
        if resp.status_code == 200:
            data = resp.json()
            print(f"SUCCESS: Issue created at {data['issue_url']}")
            print(f"Issue Number: {data['issue_number']}")
        else:
            print(f"FAILED: {resp.status_code} - {resp.text}")
            return

    # 2. Verify metadata update
    print(f"\n--- Verifying Metadata Update ---")
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{base_url}/api/forensics/{scan_id}/artifacts/{artifact_id}/")
        if resp.status_code == 200:
            artifact = resp.json()
            metadata = artifact.get("metadata", {})
            print(f"Status in Metadata: {metadata.get('status')}")
            print(f"Issue URL in Metadata: {metadata.get('issue_url')}")
        else:
            print(f"FAILED to fetch artifact: {resp.status_code}")

    # 3. Test Self-Healing with Issue Context
    print(f"\n--- Triggering Self-Healing (Approve & Fix) ---")
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{base_url}/api/forensics/{scan_id}/artifacts/{artifact_id}/self-heal/")
        if resp.status_code == 200:
            data = resp.json()
            print(f"SUCCESS: Pull Request created at {data['pr_url']}")
        else:
            print(f"FAILED: {resp.status_code} - {resp.text}")

if __name__ == "__main__":
    asyncio.run(test_staged_healing())
