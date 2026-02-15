import docker
import os
import sys

# Map of image name -> Dockerfile path
IMAGES = {
    "matrix-sqli-lab": ("Dockerfile.sql_injection", "."),
    "matrix-xss-lab": ("Dockerfile.xss", "."),
    "matrix-rce-lab": ("Dockerfile.rce", ".")
}

def build_labs():
    client = docker.from_env()
    base_path = os.path.join(os.path.dirname(__file__), "../vulnerable_apps")
    
    print("🏗️  Building Matrix Security Labs...")
    
    for image_name, (dockerfile, context) in IMAGES.items():
        print(f"   > Building {image_name}...")
        try:
            # Full path to dockerfile
            dockerfile_path = os.path.join(base_path, dockerfile)
            
            # The context path usually needs to be the directory containing the files
            # Since our files are in vulnerable_apps, we effectively run from there
            
            # Note: docker-py build command takes 'path' as the build context
            image, logs = client.images.build(
                path=base_path,
                dockerfile=dockerfile,
                tag=f"{image_name}:latest",
                rm=True
            )
            print(f"   ✅ Built {image_name} successfully.")
        except Exception as e:
            print(f"   ❌ Failed to build {image_name}: {e}")

    print("\n🎉 All labs build process completed.")

if __name__ == "__main__":
    build_labs()
