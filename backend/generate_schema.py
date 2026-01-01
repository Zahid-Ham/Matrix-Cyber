import json
import sys
import os

# Add current directory to path so we can import app
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import app

def generate_schema():
    print("Generating OpenAPI schema...")
    openapi_data = app.openapi()
    
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "openapi.json")
    
    with open(output_path, "w") as f:
        json.dump(openapi_data, f, indent=2)
    
    print(f"Schema exported to {output_path}")

if __name__ == "__main__":
    generate_schema()
