import requests
import sys

BASE_URL = "http://localhost:8000"
EMAIL = "test_a9bf8802@example.com"
PASSWORD = "TargetPassword123!"

def trigger_scan():
    s = requests.Session()
    
    # 1. Login
    print(f"[*] Logging in as {EMAIL}...")
    try:
        resp = s.post(f"{BASE_URL}/api/v1/auth/login", data={
            "username": EMAIL,
            "password": PASSWORD
        })
        if resp.status_code != 200:
            print(f"[-] Login failed: {resp.text}")
            return
        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print(f"[+] Login successful. Token: {token[:10]}...")
    except Exception as e:
        print(f"[-] Login error: {e}")
        return

    # 2. Trigger Scan
    print("[*] Triggering scan...")
    try:
        target = "http://testphp.vulnweb.com"
        resp = s.post(
            f"{BASE_URL}/api/v1/scans/",
            headers=headers,
            json={
                "target_url": target,
                "scan_type": "full",
                "agents_enabled": ["xss_agent", "sql_injection_agent"]
            }
        )
        if resp.status_code in [200, 201]:
            data = resp.json()
            print(f"[+] Scan triggered! ID: {data['id']}")
        else:
            print(f"[-] Scan trigger failed: {resp.text}")
    except Exception as e:
        print(f"[-] Scan error: {e}")

if __name__ == "__main__":
    trigger_scan()
