import requests
import time

BASE_URL = "http://localhost:8002"

def test_rate_limiting():
    print("[*] Testing Rate Limiting on /api/auth/login...")
    print("[*] Limit is 5 requests per minute.")
    
    url = f"{BASE_URL}/api/auth/login"
    payload = {
        "email": "test_auth_user@matrix.com", 
        "password": "WrongPasswordButThatIsOkay" 
    }
    
    for i in range(1, 10):
        try:
            resp = requests.post(url, json=payload)
            print(f"Request {i}: Status {resp.status_code}")
            
            if resp.status_code == 429:
                print(f"[+] PASS: Rate limit hit on request {i}!")
                return True
                
        except Exception as e:
            print(f"[!] Request {i} failed: {e}")
            
        # time.sleep(0.1) 
        
    print("[!] FAIL: Rate limit was not hit after 9 requests.")
    return False

if __name__ == "__main__":
    if test_rate_limiting():
        print("\n[SUCCESS] Rate Limiting Verified.")
    else:
        print("\n[FAILURE] Rate Limiting Failed.")
