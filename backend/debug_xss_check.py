
import html
import re
import logging

# Mock logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class XSSContext:
    HTML_BODY = "html_body"

def _is_xss_reflected(payload: str, response: str, context: str = XSSContext.HTML_BODY) -> bool:
    # Check for exact reflection (no encoding)
    if payload in response:
        print(f"Exact match: {payload}")
        return True

    # Check for HTML entity encoding (safe)
    encoded_payload = html.escape(payload)
    if encoded_payload in response and payload not in response:
        print(f"Safe encoded match: {encoded_payload}")
        return False
    else:
        print(f"Encoded check failed. Encoded: {encoded_payload} in response? {encoded_payload in response}")

    # Context-specific dangerous pattern checks
    dangerous_patterns = [
        r"<script[^>]*>.*?alert",
        r"<svg[^>]*onload",
        r"<img[^>]*onerror",
        r"<body[^>]*onload",
        r"<iframe[^>]*src\s*=\s*[\"']?javascript:",
        r"<details[^>]*ontoggle",
        r"<video[^>]*onerror",
    ]

    # Check for dangerous patterns in response
    for pattern in dangerous_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            if re.search(pattern, response, re.IGNORECASE):
                print(f"Dangerous pattern found: {pattern}")
                return True

    return False

# Scenario from test
payload = "<script>alert(1)</script>"
# My test mock only replaced < and >
encoded_in_response = payload.replace("<", "&lt;").replace(">", "&gt;")
response = f"<html><body>Search: {encoded_in_response}</body></html>"

print(f"Payload: {payload}")
print(f"Response: {response}")

result = _is_xss_reflected(payload, response)
print(f"Result: {result}")
