import asyncio
import httpx
import json
import time
import sys

BASE_URL = "http://127.0.0.1:8000"
TARGET_URL = "http://testphp.vulnweb.com"

async def run_test():
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        print("[*] Initializing CSRF...")
        # 1. Get CSRF Token
        csrf_resp = await client.get("/api/csrf/")
        if csrf_resp.status_code != 200:
            print(f"[-] Failed to get CSRF token: {csrf_resp.text}")
            return
        
        
        # Get CSRF Token from cookies (set by middleware)
        csrf_token = client.cookies.get("CSRF-TOKEN")
        if not csrf_token:
            # Fallback to JSON if expecting it there, but we know it's in cookie
            csrf_token = csrf_resp.json().get("csrf_token")
            
        if not csrf_token:
            print("[-] CSRF Token not found in cookies or JSON")
            return

        client.cookies.set("CSRF-TOKEN", csrf_token)
        headers = {"X-CSRF-Token": csrf_token}
        print(f"[+] CSRF Token initialized: {csrf_token[:10]}...")

        # 2. Login / Register
        import uuid
        random_suffix = str(uuid.uuid4())[:8]
        email = f"test_{random_suffix}@example.com"
        password = "TargetPassword123!"
        print(f"[*] Using credentials: {email} / {password}")

        print("[*] Registering new user...")
        reg_resp = await client.post("/api/auth/register/", json={
            "email": email,
            "username": email.split("@")[0],
            "password": password,
            "full_name": "Test User"
        }, headers=headers)
        
        if reg_resp.status_code != 200:
             print(f"[-] Registration failed: {reg_resp.text}")
             return

        print("[+] Registration successful, logging in...")
        login_resp = await client.post("/api/auth/login/", json={
            "email": email,
            "password": password
        }, headers=headers)
        
        # Login check handled above

        if login_resp.status_code == 200:
            print("[+] Login successful")
            token = login_resp.json()["access_token"]
            headers["Authorization"] = f"Bearer {token}"

        # 3. Trigger Scan
        print(f"[*] Triggering scan for {TARGET_URL}...")
        scan_payload = {
            "target_url": TARGET_URL,
            "scan_type": "full",
            "recursive": True,
            "max_depth": 3
        }
        
        scan_resp = await client.post("/api/scans/", json=scan_payload, headers=headers)
        if scan_resp.status_code != 201:
            print(f"[-] Failed to start scan: {scan_resp.text}")
            # Check if it fails due to CSRF again
            return

        scan_data = scan_resp.json()
        scan_id = scan_data["id"]
        print(f"[+] Scan started! ID: {scan_id}")

        # 4. Monitor Scan
        print("[*] Monitoring scan progress...")
        
        status = "pending"
        max_retries = 120 # 4 minutes max
        
        for i in range(max_retries):
            status_resp = await client.get(f"/api/scans/{scan_id}", headers=headers)
            if status_resp.status_code != 200:
                print(f"[-] Failed to get status: {status_resp.text}")
                break
                
            scan_info = status_resp.json()
            status = scan_info["status"]
            vulns = scan_info.get("total_vulnerabilities", 0)
            
            sys.stdout.write(f"\r[*] Status: {status} | Vulns: {vulns} | Time: {i*2}s")
            sys.stdout.flush()
            
            if status in ["completed", "failed", "stopped"]:
                print("\n")
                print(f"[+] Final Status: {status}")
                print(f"[+] Total Vulnerabilities: {vulns}")
                
                if vulns > 0:
                    print("[SUCCESS] Vulnerabilities detected!")
                else:
                    print("[WARNING] Zero vulnerabilities found - check logs.")
                break
            
            time.sleep(2)

if __name__ == "__main__":
    asyncio.run(run_test())
