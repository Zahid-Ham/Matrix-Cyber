import requests
import uuid

BASE_URL = "http://127.0.0.1:8000"

def trigger():
    try:
        # Generate clean credentials
        suffix = str(uuid.uuid4())[:8]
        email = f"user_{suffix}@example.com"
        username = f"user_{suffix}"
        password = "TargetPassword123!"
        
        s = requests.Session()
        
        # 1. CSRF
        print("[*] Getting CSRF...")
        r = s.get(f"{BASE_URL}/api/csrf/")
        csrf = r.json().get("csrf_token")
        if not csrf:
            csrf = r.cookies.get("CSRF-TOKEN")
        
        headers = {
            "X-CSRF-Token": csrf,
            "Content-Type": "application/json"
        }
        s.headers.update(headers)
        print(f"[+] CSRF: {csrf[:10]}")
        
        # 2. Register
        print(f"[*] Registering {email}...")
        payload = {
            "email": email,
            "username": username,
            "password": password,
            "full_name": "Test User"
        }
        r = s.post(f"{BASE_URL}/api/auth/register/", json=payload)
        if r.status_code != 201:
            print(f"[-] Register failed: {r.text}")
            # Try login if exists (unlikely with uuid)
            
        print("[+] Registration OK")
        
        # 3. Login
        print("[*] Logging in...")
        r = s.post(f"{BASE_URL}/api/auth/login", json={
            "email": email, 
            "password": password
        })
        if r.status_code != 200:
             print(f"[-] Login failed: {r.text}")
             return
             
        token = r.json()["access_token"]
        s.headers.update({"Authorization": f"Bearer {token}"})
        print(f"[+] Token: {token[:10]}")
        
        # 4. Trigger
        print("[*] Triggering scan...")
        r = s.post(f"{BASE_URL}/api/scans/", json={
            "target_url": "http://testphp.vulnweb.com",
            "scan_type": "full",
            "agents_enabled": ["xss", "sql_injection"]
        })
        if r.status_code != 201:
            print(f"[-] Scan trigger failed: {r.text}")
            return
            
        scan_id = r.json()["id"]
        print(f"[+] Scan started: {scan_id}")
        
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    trigger()
