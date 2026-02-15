import httpx
import asyncio
import os

TOKEN = os.getenv("GITHUB_TOKEN", "your_github_pat_here")
OWNER = "iqrasayed466-star"
REPO = "testrepo"

async def check_permissions():
    headers = {
        "Authorization": f"token {TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    async with httpx.AsyncClient() as client:
        print(f"Checking token against https://api.github.com/repos/{OWNER}/{REPO}...")
        
        # 1. Check Repo Access
        resp = await client.get(f"https://api.github.com/repos/{OWNER}/{REPO}", headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            perms = data.get("permissions", {})
            print(f"✅ Repo access confirm.")
            print(f"Permissions: {perms}")
            if not perms.get("push"):
                print("❌ Token matches repo but MISSING 'push' permission.")
        else:
            print(f"❌ Failed to access repo: {resp.status_code}")
            print(resp.text)
            return

        # 2. Check Token Scopes
        print(f"Token Scopes: {resp.headers.get('X-OAuth-Scopes', 'None')}")
        
        # 3. Try to Create a dummy ref (Dry run logic essentially)
        # We won't actually create one to avoid littering, but we can check if we can read refs
        resp = await client.get(f"https://api.github.com/repos/{OWNER}/{REPO}/git/refs/heads", headers=headers)
        if resp.status_code == 200:
            print(f"✅ Can read refs.")
        else:
            print(f"❌ Cannot read refs: {resp.status_code}")

if __name__ == "__main__":
    asyncio.run(check_permissions())
