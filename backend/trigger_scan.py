import requests

url = "http://127.0.0.1:8000/api/scans/"
payload = {
    "target_url": "https://github.com/iqrasayed466-star/testrepo",
    "scan_type": "repo",
    "user_id": 1,
    "agents_enabled": True
}

session = requests.Session()

try:
    print("Fetching CSRF token...")
    # Hit the dedicated CSRF initialization endpoint
    csrf_resp = session.get("http://127.0.0.1:8000/api/csrf/")
    csrf_data = csrf_resp.json()
    csrftoken = csrf_data.get("csrf_token")
    print(f"Got CSRF token: {csrftoken}")
    
    # Manually set the cookie since we got it from JSON body, not Set-Cookie header
    session.cookies.set("CSRF-TOKEN", csrftoken)
    
    headers = {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrftoken,
    }

    print(f"Sending scan request to {url}...")
    response = session.post(url, json=payload, headers=headers)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"Error: {e}")
