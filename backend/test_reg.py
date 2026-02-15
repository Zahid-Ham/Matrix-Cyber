import requests
import json

def test_registration():
    session = requests.Session()
    health_url = "http://localhost:8000/health"
    reg_url = "http://localhost:8000/api/auth/register"
    
    # 1. Get CSRF token
    print(f"Getting CSRF token from {health_url}...")
    session.get(health_url)
    csrf_token = session.cookies.get('CSRF-TOKEN')
    print(f"CSRF Token: {csrf_token}")
    
    headers = {}
    if csrf_token:
        headers['X-CSRF-Token'] = csrf_token

    payload = {
        "email": "debug_user@example.com",
        "username": "debug_user",
        "password": "Password123!",
        "full_name": "Debug User",
        "company": "Debug Corp"
    }
    
    import time
    timestamp = int(time.time())
    payload["email"] = f"debug_{timestamp}@example.com"
    payload["username"] = f"user_{timestamp}"
    
    print(f"Testing registration at {reg_url}...")
    try:
        response = session.post(reg_url, json=payload, headers=headers, timeout=10)
        print(f"Status Code: {response.status_code}")
        try:
            print("Response JSON:")
            print(json.dumps(response.json(), indent=2))
        except:
            print(f"Response Text: {response.text}")
    except Exception as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    test_registration()
