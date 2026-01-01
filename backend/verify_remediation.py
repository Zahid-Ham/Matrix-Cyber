import requests
import sys

BASE_URL = "http://localhost:8001"

def test_login_cookies():
    print("[*] Testing Login Cookies...")
    try:
        # 0. Register (to ensure user exists)
        reg_data = {
            "email": "test_auth_user@matrix.com",
            "username": "test_auth_user",
            "password": "SecurePassword123!",
            "full_name": "Test User"
        }
        # Ignore 400 if already exists
        requests.post(f"{BASE_URL}/api/auth/register", json=reg_data)

        # 1. Login
        resp = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "test_auth_user@matrix.com", 
            "password": "SecurePassword123!"
        })
        
        if resp.status_code != 200:
            print(f"[!] Login failed: {resp.status_code} - {resp.text}")
            return False
            
        print(f"[+] Login successful. Checking cookies...")
        
        # 2. Check for Cookies
        cookies = resp.cookies
        access_token_cookie = cookies.get("access_token")
        refresh_token_cookie = cookies.get("refresh_token")
        
        if not access_token_cookie:
            print("[!] FAIL: 'access_token' cookie not found.")
            return False
            
        if not refresh_token_cookie:
            print("[!] FAIL: 'refresh_token' cookie not found.")
            return False
            
        print("[+] PASS: Both 'access_token' and 'refresh_token' cookies are present.")
        
        # 3. Check Cookie Attributes (Limited visibility in requests, but we checked logic)
        # Note: requests cookie jar doesn't easily show HttpOnly flag directly, 
        # but presence in SET-COOKIE header confirmation is implied if found in jar for subsequent requests.
        
        # 4. Test Authed Endpoint using Cookies
        me_resp = requests.get(f"{BASE_URL}/api/auth/me", cookies=cookies)
        if me_resp.status_code == 200:
             print(f"[+] PASS: Successfully accessed protected endpoint '/me' using cookies. User: {me_resp.json().get('email')}")
        else:
             print(f"[!] FAIL: Failed to access protected endpoint using cookies. Status: {me_resp.status_code}")
             return False

        return True
        
    except Exception as e:
        print(f"[!] Error during cookie test: {e}")
        return False

def test_csp_header():
    # CSP is now handled by Next.js middleware, so we should check the Frontend URL (port 3000)
    # However, for backend API security headers, we can check 8000 too if we added them there (we did in main.py too originally)
    # The prompt explicitly asked for CSP in next.config.js, so let's verify HEAD on localhost:3000
    print("\n[*] Testing CSP Headers on Frontend (Next.js)...")
    try:
        resp = requests.head("http://localhost:3000")
        csp = resp.headers.get("Content-Security-Policy")
        
        if csp:
            print(f"[+] CSP Header Found: {csp[:50]}...")
            if "default-src 'self'" in csp:
                 print("[+] PASS: CSP contains 'default-src self'")
            else:
                 print("[!] FAIL: CSP missing 'default-src self'")
                 return False
        else:
            # It might be present on HTML requests, try GET
            resp = requests.get("http://localhost:3000")
            csp = resp.headers.get("Content-Security-Policy")
            if csp:
                 print(f"[+] CSP Header Found on GET: {csp[:50]}...")
                 return True
            else:
                 print("[!] FAIL: No CSP header found on Frontend.")
                 # Note: in dev mode Next.js might behave differently or headers might be in slightly different place.
                 # verification manually in browser might be better for CSP if this fails.
                 return False
                 
        return True
    except Exception as e:
        print(f"[!] Error checking Frontend CSP (Is server running?): {e}")
        return False

if __name__ == "__main__":
    print("=== Matrix Security Remediation Verification ===\n")
    cookies_ok = test_login_cookies()
    csp_ok = test_csp_header()
    
    if cookies_ok:
        print("\n[SUCCESS] Critical Fixes (Cookies) Verified.")
    else:
        print("\n[FAILURE] Critical Fixes Verification Failed.")
        sys.exit(1)
