import requests

BASE_URL = "http://localhost:8002"

def test_csrf():
    print("[*] Testing CSRF Protection...")
    
    # 1. GET to obtain cookie
    session = requests.Session()
    resp = session.get(f"{BASE_URL}/") # Root info endpoint
    
    if resp.status_code != 200:
        print(f"[!] GET /api/ failed: {resp.status_code}")
        return False
        
    csrf_token = resp.cookies.get("CSRF-TOKEN")
    if not csrf_token:
        print("[!] FAIL: CSRF-TOKEN cookie not set on GET request.")
        # Note: Middleware sets it on GET.
        return False
        
    print(f"[+] CSRF Cookie obtained: {csrf_token[:10]}...")
    
    # 2. POST without Header (should be 403)
    # targeting /api/auth/logout which is a POST and requires no body (simpler)
    # But it requires auth? No, logout just clears cookies.
    # Actually CSRF middleware runs before Auth.
    resp = session.post(f"{BASE_URL}/api/auth/logout")
    
    if resp.status_code == 403:
        print("[+] PASS: POST without CSRF header rejected (403).")
    else:
        print(f"[!] FAIL: POST without CSRF header returned {resp.status_code} (Expected 403).")
        return False
        
    # 3. POST with Header (should be 200 or 401, but NOT 403)
    headers = {
        "X-CSRF-Token": csrf_token
    }
    resp = session.post(f"{BASE_URL}/api/auth/logout", headers=headers)
    
    if resp.status_code != 403:
        print(f"[+] PASS: POST with CSRF header accepted (Status: {resp.status_code}).")
    else:
        print(f"[!] FAIL: POST with CSRF header rejected (403).")
        return False
        
    return True

if __name__ == "__main__":
    if test_csrf():
        print("\n[SUCCESS] CSRF Protection Verified.")
    else:
        print("\n[FAILURE] CSRF Protection Failed.")
